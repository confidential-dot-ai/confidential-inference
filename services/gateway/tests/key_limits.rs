//! Per-key rate limits and token budgets from the key snapshot, enforced
//! before the gateway forwards a request upstream.
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use confidential_gateway::{
    AuditEvent, AuditSink, GatewayConfig,
    api_keys::KeyStore,
    key_limits::{BudgetWindow, window_start},
    key_registry::SnapshotPush,
    metrics::{GatewayMetrics, MetricsSource},
    protection::ProtectionConfig,
    router_with_usage,
    usage::{MAX_PENDING_EVENTS, Model, Recorder},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const PEPPER: [u8; 32] = [7; 32];
const LIMITED_ID: &str = "key_limited_0123456789abcdef";
const OTHER_ID: &str = "key_other_0123456789abcdef01";

struct Audit;
impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

fn fingerprint() -> String {
    hex::encode(
        Sha256::new()
            .chain_update(b"confidential.ai/gateway-pepper-fingerprint/v1")
            .chain_update(PEPPER)
            .finalize(),
    )
}

fn row(id: &str, plaintext: &str, rate_limit: &Value, token_budget: &Value) -> Value {
    let mut mac = Hmac::<Sha256>::new_from_slice(&PEPPER).unwrap_or_else(|_| unreachable!());
    mac.update(plaintext.as_bytes());
    json!({
        "id": id, "name": "test", "owner": "unknown", "prefix": "synthetic",
        "keyHash": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
        "pepperFingerprint": fingerprint(), "tags": [],
        "rateLimit": rate_limit, "tokenBudget": token_budget,
        "createdAt": "2026-11-13T00:00:00Z", "createdBy": "operator",
        "revokedAt": null, "revokedBy": null, "version": 1
    })
}

#[allow(clippy::needless_pass_by_value)]
fn snapshot(revision: i64, rows: Vec<Value>, token_usage: Option<Value>) -> SnapshotPush {
    let mut body = json!({
        "schemaVersion": "confidential.ai/key-registry-snapshot/v1",
        "environment": "staging",
        "revision": revision,
        "generatedAt": "2026-11-13T00:00:00Z",
        "pepperFingerprint": fingerprint(),
        "keys": rows,
    });
    if let Some(usage) = token_usage {
        body["tokenUsage"] = usage;
    }
    serde_json::from_value(body).unwrap_or_else(|error| panic!("{error}"))
}

fn rfc3339(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .unwrap_or_else(|_| unreachable!())
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| unreachable!())
}

/// An upstream that counts the requests it receives and reports 10 input
/// and 5 output tokens for each.
async fn start_upstream() -> Result<(SocketAddr, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let received = Arc::new(AtomicUsize::new(0));
    let counter = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let app = Router::new().route(
            "/v1/chat/completions",
            post(move |Json(_): Json<Value>| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Json(
                        json!({"model":"model-a","choices":[{"message":{"content":"ok"}}],
                        "usage":{"prompt_tokens":10,"completion_tokens":5}}),
                    )
                }
            }),
        );
        axum::serve(listener, app).await
    });
    Ok((address, received))
}

fn app(keys: Arc<KeyStore>, upstream: SocketAddr, metrics: Arc<GatewayMetrics>) -> Router {
    let models = BTreeMap::from([(
        "model-a".to_owned(),
        Model {
            served_model: "model-a".into(),
            model_revision: "revision-1".into(),
        },
    )]);
    let recorder = Recorder::new("gateway-test", models, MAX_PENDING_EVENTS, metrics.clone());
    router_with_usage(
        GatewayConfig {
            catalog_model_ids: vec!["model-a".into()],
            inference_model_ids: vec!["model-a".into()],
            upstream_base_url: format!("http://{upstream}"),
            maximum_body_bytes: 4096,
            upstream_timeout: Duration::from_secs(5),
            protection: ProtectionConfig::default(),
        },
        keys,
        Arc::new(Audit),
        metrics,
        reqwest::Client::new(),
        Some(recorder),
    )
}

async fn send(
    app: &Router,
    bearer: &str,
) -> Result<(StatusCode, Option<String>, Value), Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/chat/completions")
                .method("POST")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"model":"model-a","messages":[{"role":"user","content":"hi"}]})
                        .to_string(),
                ))?,
        )
        .await?;
    let status = response.status();
    let retry_after = response
        .headers()
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let bytes = axum::body::to_bytes(response.into_body(), 65_536).await?;
    Ok((
        status,
        retry_after,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

fn store() -> Result<Arc<KeyStore>, String> {
    Ok(Arc::new(
        KeyStore::new(PEPPER.to_vec(), "staging").map_err(|error| format!("{error:?}"))?,
    ))
}

#[tokio::test]
async fn the_rate_limit_refuses_before_the_upstream_and_names_no_key()
-> Result<(), Box<dyn std::error::Error>> {
    let keys = store()?;
    keys.apply(&snapshot(
        1,
        vec![
            row(
                LIMITED_ID,
                "limited-key",
                &json!({"requestsPerMinute": 1, "burst": 2}),
                &Value::Null,
            ),
            row(OTHER_ID, "other-key", &Value::Null, &Value::Null),
        ],
        None,
    ))
    .map_err(|error| format!("{error:?}"))?;
    let (upstream, received) = start_upstream().await?;
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let app = app(keys, upstream, metrics.clone());

    for _ in 0..2 {
        assert_eq!(send(&app, "limited-key").await?.0, StatusCode::OK);
    }
    let (status, retry_after, body) = send(&app, "limited-key").await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = retry_after.ok_or("no Retry-After")?.parse()?;
    assert!((1..=60).contains(&retry_after), "{retry_after}");
    assert_eq!(body["error"]["code"], "rate_limit_exceeded");
    let text = body.to_string();
    for secret in [LIMITED_ID, OTHER_ID, "limited-key", "requestsPerMinute"] {
        assert!(!text.contains(secret), "{text}");
    }
    assert_eq!(received.load(Ordering::SeqCst), 2);

    // Another key has no limit and is not affected.
    for _ in 0..5 {
        assert_eq!(send(&app, "other-key").await?.0, StatusCode::OK);
    }
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("reason=\"rate_limit_exceeded\""),
        "{rendered}"
    );
    Ok(())
}

#[tokio::test]
async fn the_token_budget_counts_admin_and_local_spend() -> Result<(), Box<dyn std::error::Error>> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let day = window_start(BudgetWindow::Day, now);
    let keys = store()?;
    let budget = json!({"tokens": 100, "window": "day"});
    // The admin measured 80 tokens. One request adds 15: 95 is still under
    // the budget. The next one makes 110, then the key is refused.
    keys.apply(&snapshot(
        1,
        vec![row(LIMITED_ID, "limited-key", &Value::Null, &budget)],
        Some(json!({"asOf": rfc3339(now - 60), "keys": [
            {"id": LIMITED_ID, "windowStart": rfc3339(day), "tokens": 80}
        ]})),
    ))
    .map_err(|error| format!("{error:?}"))?;
    let (upstream, received) = start_upstream().await?;
    let app = app(
        keys.clone(),
        upstream,
        Arc::new(GatewayMetrics::new("staging")),
    );

    assert_eq!(send(&app, "limited-key").await?.0, StatusCode::OK);
    assert_eq!(keys.spent_tokens(LIMITED_ID), Some(95));
    assert_eq!(send(&app, "limited-key").await?.0, StatusCode::OK);
    let (status, retry_after, body) = send(&app, "limited-key").await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "insufficient_quota");
    let retry_after: i64 = retry_after.ok_or("no Retry-After")?.parse()?;
    assert!((1..=86_400).contains(&retry_after), "{retry_after}");
    let text = body.to_string();
    assert!(
        !text.contains(LIMITED_ID) && !text.contains("100"),
        "{text}"
    );
    assert_eq!(received.load(Ordering::SeqCst), 2);

    // The same revision with a newer admin count still updates the spend:
    // the admin now reports 20 tokens (for example after a correction).
    // The local tokens inside the grace stay counted.
    keys.apply(&snapshot(
        1,
        Vec::new(),
        Some(json!({"asOf": rfc3339(now + 1), "keys": [
            {"id": LIMITED_ID, "windowStart": rfc3339(day), "tokens": 20}
        ]})),
    ))
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(keys.spent_tokens(LIMITED_ID), Some(50));
    assert_eq!(send(&app, "limited-key").await?.0, StatusCode::OK);

    // A new revision that removes the budget makes the key unlimited.
    keys.apply(&snapshot(
        2,
        vec![row(LIMITED_ID, "limited-key", &Value::Null, &Value::Null)],
        None,
    ))
    .map_err(|error| format!("{error:?}"))?;
    assert_eq!(keys.spent_tokens(LIMITED_ID), None);
    Ok(())
}

#[tokio::test]
async fn an_out_of_range_limit_refuses_the_whole_snapshot() -> Result<(), Box<dyn std::error::Error>>
{
    let keys = store()?;
    keys.apply(&snapshot(
        1,
        vec![row(LIMITED_ID, "limited-key", &Value::Null, &Value::Null)],
        None,
    ))
    .map_err(|error| format!("{error:?}"))?;
    for (rate_limit, token_budget) in [
        (json!({"requestsPerMinute": 0}), Value::Null),
        (Value::Null, json!({"tokens": 0, "window": "day"})),
    ] {
        assert!(
            keys.apply(&snapshot(
                2,
                vec![row(LIMITED_ID, "limited-key", &rate_limit, &token_budget)],
                None,
            ))
            .is_err()
        );
    }
    let bad_usage = snapshot(
        2,
        Vec::new(),
        Some(json!({"asOf": "not-a-time", "keys": []})),
    );
    assert!(keys.apply(&bad_usage).is_err());
    assert_eq!(keys.cached_revision(), Some(1));
    // An unknown window does not parse at all.
    let unknown_window: Result<SnapshotPush, _> = serde_json::from_value(json!({
        "schemaVersion": "confidential.ai/key-registry-snapshot/v1",
        "environment": "staging", "revision": 3, "keys": [
            row(LIMITED_ID, "limited-key", &Value::Null, &json!({"tokens": 5, "window": "week"}))
        ]
    }));
    assert!(unknown_window.is_err());
    Ok(())
}
