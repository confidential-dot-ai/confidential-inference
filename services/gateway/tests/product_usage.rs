//! The stateless gateway against a local HTTPS admin: the key pull, the
//! readiness gate, usage events and the pinned admin CA.
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    http::{HeaderMap, Request, StatusCode, header},
    response::IntoResponse,
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig,
    admin_client::{self, AdminClient, Config},
    api_keys::{KeyStore, admin_router},
    metrics::GatewayMetrics,
    metrics::MetricsSource,
    protection::ProtectionConfig,
    router_with_usage,
    usage::{MAX_PENDING_EVENTS, Model, Outcome, Recorder},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const TOKEN: &str = "gateway-token-0123456789abcdef0123456789";
const PEPPER: [u8; 32] = [7; 32];

struct Audit;
impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

#[derive(Default)]
struct Admin {
    events: Mutex<Vec<Value>>,
    failing: Mutex<bool>,
    /// Answer 413 for a larger batch (0: no limit).
    max_batch: Mutex<usize>,
}

fn snapshot() -> Value {
    let fingerprint = hex::encode(
        Sha256::new()
            .chain_update(b"confidential.ai/gateway-pepper-fingerprint/v1")
            .chain_update(PEPPER)
            .finalize(),
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&PEPPER).unwrap_or_else(|_| unreachable!());
    mac.update(b"synthetic-key");
    json!({
        "schemaVersion": "confidential.ai/key-registry-snapshot/v1",
        "environment": "staging",
        "revision": 7,
        "generatedAt": "2026-10-22T00:00:00Z",
        "pepperFingerprint": fingerprint,
        "keys": [{
            "id": "key_admin_exact_id", "name": "test", "owner": "unknown", "prefix": "synthetic",
            "keyHash": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
            "pepperFingerprint": fingerprint, "tags": [], "rateLimit": null,
            "createdAt": "2026-10-22T00:00:00Z", "createdBy": "operator", "revokedAt": null,
            "revokedBy": null, "version": 1
        }]
    })
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(&format!("Bearer {TOKEN}"))
}

async fn start_admin(
    admin: Arc<Admin>,
) -> Result<(SocketAddr, String), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["admin.test".to_owned()])?;
    let certificate = certified.cert.pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate.clone().into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
    )
    .await?;
    let app = Router::new()
        .route(
            "/api/gateway/key-snapshot",
            get(|headers: HeaderMap| async move {
                if authorized(&headers) {
                    Json(snapshot()).into_response()
                } else {
                    StatusCode::UNAUTHORIZED.into_response()
                }
            }),
        )
        .route(
            "/api/usage/ingest",
            post(
                |axum::extract::State(admin): axum::extract::State<Arc<Admin>>,
                 headers: HeaderMap,
                 Json(body): Json<Value>| async move {
                    if !authorized(&headers) {
                        return StatusCode::UNAUTHORIZED.into_response();
                    }
                    if *admin.failing.lock().unwrap_or_else(|_| unreachable!()) {
                        return StatusCode::SERVICE_UNAVAILABLE.into_response();
                    }
                    let events = body["events"].as_array().cloned().unwrap_or_default();
                    let max_batch = *admin.max_batch.lock().unwrap_or_else(|_| unreachable!());
                    if max_batch > 0 && events.len() > max_batch {
                        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                    }
                    if events.iter().any(|event| event["key_id"] == "key_poison") {
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    let count = events.len();
                    admin
                        .events
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .extend(events);
                    Json(json!({"inserted": count})).into_response()
                },
            ),
        )
        .with_state(admin);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    tokio::spawn(axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service()));
    Ok((address, certificate))
}

async fn start_upstream() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let app = Router::new().route("/v1/chat/completions", post(|Json(payload): Json<Value>| async move {
            if payload["stream"] == true {
                assert_eq!(payload["stream_options"]["include_usage"], true);
                let text = "data: {\"model\":\"model-a\",\"choices\":[{\"delta\":{\"content\":\"private-output\"}}]}\n\ndata: {\"model\":\"model-a\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\ndata: [DONE]\n\n";
                ([(header::CONTENT_TYPE, "text/event-stream")], Body::from(Bytes::from_static(text.as_bytes()))).into_response()
            } else {
                Json(json!({"model":"model-a","choices":[{"message":{"content":"private-output"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}})).into_response()
            }
        }));
        axum::serve(listener, app).await
    });
    Ok(address)
}

fn client_config(address: SocketAddr, ca: &str) -> Config {
    serde_json::from_value(json!({
        "endpoint": format!("https://admin.test:{}/api/usage/ingest", address.port()),
        "token": TOKEN,
        "tls_ca_pem": ca,
        "connect_address": "127.0.0.1",
        "models": {"model-a": {"served_model": "model-a", "model_revision": "revision-1"}},
        // Fields of the secret the gateway does not read.
        "environment": "staging",
        "max_buckets": 128
    }))
    .unwrap_or_else(|error| panic!("{error}"))
}

#[tokio::test]
async fn keys_come_from_the_admin_and_usage_goes_back_as_events()
-> Result<(), Box<dyn std::error::Error>> {
    let admin = Arc::new(Admin::default());
    let (address, ca) = start_admin(admin.clone()).await?;
    let config = client_config(address, &ca);
    let client = Arc::new(AdminClient::new(&config)?);
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let keys = Arc::new(KeyStore::new(PEPPER.to_vec(), "staging").map_err(|e| format!("{e:?}"))?);
    assert!(!keys.is_ready());
    tokio::spawn(admin_client::sync_keys(
        client.clone(),
        keys.clone(),
        metrics.clone(),
    ));
    for _ in 0..100 {
        if keys.is_ready() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(keys.cached_revision(), Some(7));
    assert_eq!(
        keys.verify("synthetic-key").as_deref(),
        Some("key_admin_exact_id")
    );

    let upstream_address = start_upstream().await?;
    let models = BTreeMap::from([(
        "model-a".to_owned(),
        Model {
            served_model: "model-a".into(),
            model_revision: "revision-1".into(),
        },
    )]);
    let recorder = Recorder::new("gateway-test", models, MAX_PENDING_EVENTS, metrics.clone());
    let app = router_with_usage(
        GatewayConfig {
            catalog_model_ids: vec!["model-a".into()],
            inference_model_ids: vec!["model-a".into()],
            upstream_base_url: format!("http://{upstream_address}"),
            maximum_body_bytes: 4096,
            upstream_timeout: Duration::from_secs(5),
            protection: ProtectionConfig::default(),
        },
        keys.clone(),
        Arc::new(Audit),
        metrics.clone(),
        reqwest::Client::new(),
        Some(recorder.clone()),
    );
    let ready = app
        .clone()
        .oneshot(Request::builder().uri("/ready").body(Body::empty())?)
        .await?;
    assert_eq!(ready.status(), StatusCode::OK);
    for streaming in [false, true] {
        let response = app.clone().oneshot(Request::builder().uri("/v1/chat/completions").method("POST")
            .header("authorization", "Bearer synthetic-key").header("content-type", "application/json")
            .header("x-request-id", "caller-chosen-id")
            .body(Body::from(json!({"model":"model-a","messages":[{"role":"user","content":"private-prompt"}],"stream":streaming}).to_string()))?).await?;
        assert_eq!(response.status(), 200);
        axum::body::to_bytes(response.into_body(), 4096).await?;
    }
    assert_eq!(recorder.pending(), 2);

    // The admin fails: the events stay queued.
    *admin.failing.lock().unwrap_or_else(|_| unreachable!()) = true;
    assert!(recorder.send_pending(&client).await.is_err());
    assert_eq!(recorder.pending(), 2);
    *admin.failing.lock().unwrap_or_else(|_| unreachable!()) = false;
    recorder.send_pending(&client).await?;
    assert_eq!(recorder.pending(), 0);

    let events = admin
        .events
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .clone();
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_eq!(event["key_id"], "key_admin_exact_id");
        assert_eq!(event["outcome"], "completed");
        assert_eq!(event["input_tokens"], 10);
        assert_eq!(event["output_tokens"], 5);
        assert_eq!(event["cached_input_tokens"], 4);
        assert_eq!(event["producer_instance"], "gateway-test");
        assert_ne!(event["request_id"], "caller-chosen-id");
    }
    assert_ne!(events[0]["request_id"], events[1]["request_id"]);
    let text = serde_json::to_string(&events)?;
    assert!(!text.contains("private-"));
    assert!(!text.contains("synthetic-key"));
    Ok(())
}

#[tokio::test]
async fn the_admin_must_present_a_certificate_from_the_pinned_ca()
-> Result<(), Box<dyn std::error::Error>> {
    let (address, _) = start_admin(Arc::new(Admin::default())).await?;
    let other = rcgen::generate_simple_self_signed(vec!["admin.test".to_owned()])?;
    let client = AdminClient::new(&client_config(address, &other.cert.pem()))?;
    assert_eq!(client.key_snapshot().await.err(), Some("unreachable"));
    Ok(())
}

#[test]
fn the_admin_endpoint_must_be_https() {
    let mut config = client_config(
        "127.0.0.1:443".parse().unwrap_or_else(|_| unreachable!()),
        "",
    );
    config.tls_ca_pem = None;
    config.endpoint = "http://admin.test/api/usage/ingest".into();
    assert!(AdminClient::new(&config).is_err());
    config.endpoint = "https://admin.test/api/usage/ingest".into();
    assert!(AdminClient::new(&config).is_ok());
    config.token = "short".into();
    assert!(AdminClient::new(&config).is_err());
}

#[tokio::test]
async fn a_refused_batch_is_split_and_only_the_refused_event_is_dropped()
-> Result<(), Box<dyn std::error::Error>> {
    let admin = Arc::new(Admin::default());
    *admin.max_batch.lock().unwrap_or_else(|_| unreachable!()) = 3;
    let (address, ca) = start_admin(admin.clone()).await?;
    let client = AdminClient::new(&client_config(address, &ca))?;
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let models = BTreeMap::from([(
        "model-a".to_owned(),
        Model {
            served_model: "model-a".into(),
            model_revision: "revision-1".into(),
        },
    )]);
    let recorder = Recorder::new("gateway-test", models, MAX_PENDING_EVENTS, metrics.clone());
    for key in [
        "key_1",
        "key_2",
        "key_poison",
        "key_3",
        "key_4",
        "key_5",
        "key_6",
    ] {
        let mut request = recorder.reserve(key, "model-a").ok_or("unknown model")?;
        request.finish(Outcome::Completed);
    }
    // 413 for more than 3 events, 400 for a batch with the poison event:
    // neither blocks the queue.
    recorder.send_pending(&client).await?;
    assert_eq!(recorder.pending(), 0);
    let stored: Vec<_> = admin
        .events
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .iter()
        .map(|event| event["key_id"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(
        stored,
        ["key_1", "key_2", "key_3", "key_4", "key_5", "key_6"]
    );
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("gateway_usage_events_rejected_total{status=\"400\",env=\"staging\"} 1"),
        "{rendered}"
    );
    Ok(())
}

#[tokio::test]
async fn with_no_egress_a_push_makes_the_gateway_ready_and_failed_pulls_keep_it()
-> Result<(), Box<dyn std::error::Error>> {
    // Nothing listens at the admin address: every pull and send fails, as
    // under the c8s per-pod mesh before declared egress (C8s#1047). The
    // gateway is not ready until a snapshot lands.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let ca = rcgen::generate_simple_self_signed(vec!["admin.test".to_owned()])?
        .cert
        .pem();
    let client = Arc::new(AdminClient::new(&client_config(closed, &ca))?);
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let keys = Arc::new(KeyStore::new(PEPPER.to_vec(), "staging").map_err(|e| format!("{e:?}"))?);
    tokio::spawn(admin_client::sync_keys(
        client.clone(),
        keys.clone(),
        metrics.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!keys.is_ready());

    let response = admin_router(keys.clone())
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/admin/v1/api-keys/snapshot")
                .header("content-type", "application/json")
                .body(Body::from(snapshot().to_string()))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(keys.is_ready());

    // The next pull fails too; the pushed keys stay and the gateway stays ready.
    tokio::time::sleep(Duration::from_millis(5_500)).await;
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains(
            "gateway_key_registry_fetch_failed_total{reason=\"unreachable\",env=\"staging\"} 2"
        ),
        "{rendered}"
    );
    assert_eq!(
        keys.verify("synthetic-key").as_deref(),
        Some("key_admin_exact_id")
    );

    // Usage cannot leave: the queue keeps the newest events up to its bound.
    let models = BTreeMap::from([(
        "model-a".to_owned(),
        Model {
            served_model: "model-a".into(),
            model_revision: "revision-1".into(),
        },
    )]);
    let recorder = Recorder::new("gateway-test", models, 3, metrics.clone());
    for key in ["key_1", "key_2", "key_3", "key_4", "key_5"] {
        let mut request = recorder.reserve(key, "model-a").ok_or("unknown model")?;
        request.finish(Outcome::Completed);
    }
    assert_eq!(recorder.send_pending(&client).await, Err("unreachable"));
    assert_eq!(recorder.pending(), 3);
    let rendered = metrics.render_prometheus();
    assert!(
        rendered.contains("gateway_usage_events_dropped_total{env=\"staging\"} 2"),
        "{rendered}"
    );
    Ok(())
}
