//! Exercise request handling, stream rewriting, and the real disk queue.
use axum::{
    Json, Router,
    body::{Body, Bytes},
    http::{Request, header},
    response::IntoResponse,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayAvailability, GatewayConfig,
    UnavailableAttestation,
    metrics::GatewayMetrics,
    protection::ProtectionConfig,
    router_with_runtime_and_usage,
    usage::{Config, Model, Recorder, now_ms},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tower::ServiceExt;

struct Keys;
impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, value: &str) -> Option<String> {
        (value == "synthetic-key").then(|| "key_admin_exact_id".into())
    }
}
struct Audit;
impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

#[tokio::test]
async fn requests_become_private_minute_totals_with_internal_stream_usage()
-> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let upstream = tokio::spawn(async move {
        let app = Router::new().route("/v1/chat/completions", post(|Json(payload): Json<Value>| async move {
            if payload["stream"] == true {
                assert_eq!(payload["stream_options"]["include_usage"], true);
                let text = "data: {\"model\":\"model-a\",\"choices\":[{\"delta\":{\"content\":\"private-output-日\"}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":1}}\n\ndata: {\"model\":\"model-a\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\ndata: [DONE]\n\n";
                let chunks: Vec<_> = text.as_bytes().iter().map(|b| Ok::<_, std::io::Error>(Bytes::from(vec![*b]))).collect();
                ([(header::CONTENT_TYPE, "text/event-stream")], Body::from_stream(futures_util::stream::iter(chunks))).into_response()
            } else { Json(json!({"model":"model-a", "choices":[{"message":{"content":"private-output"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}})).into_response() }
        }));
        axum::serve(listener, app).await
    });
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("usage.sqlite3");
    let recorder = Recorder::open(
        &file,
        Config {
            environment: "staging".into(),
            cluster_id: "cluster-test".into(),
            key_realm: "staging".into(),
            producer_id: "producer-test".into(),
            endpoint: "https://admin.example.test/api/usage/ingest".into(),
            token: "a".repeat(48),
            tls_identity_pem: None,
            tls_ca_pem: None,
            connect_address: None,
            models: BTreeMap::from([(
                "model-a".into(),
                Model {
                    served_model: "model-a".into(),
                    model_revision: "revision-1".into(),
                },
            )]),
            max_buckets: 128,
            max_database_bytes: 4_194_304,
            acknowledged_retention_seconds: 3600,
        },
    )?;
    let app = router_with_runtime_and_usage(
        GatewayConfig {
            catalog_model_ids: vec!["model-a".into()],
            inference_model_ids: vec!["model-a".into()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 4096,
            upstream_timeout: Duration::from_secs(5),
            protection: ProtectionConfig::default(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("staging")),
        GatewayAvailability::default(),
        Arc::new(UnavailableAttestation),
        reqwest::Client::new(),
        None,
        None,
        Some(recorder.clone()),
    );
    for streaming in [false, true] {
        let response = app.clone().oneshot(Request::builder().uri("/v1/chat/completions").method("POST").header("authorization", "Bearer synthetic-key").header("content-type", "application/json").body(Body::from(json!({"model":"model-a","messages":[{"role":"user","content":"private-prompt-canary"}],"stream":streaming}).to_string()))?).await?;
        assert_eq!(response.status(), 200);
        let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
        let text = String::from_utf8(bytes.to_vec())?;
        if streaming {
            assert!(!text.contains("\"choices\":[]"));
            assert!(text.contains("[DONE]"));
        }
    }
    recorder.flush(now_ms())?;
    let batch = recorder.batch()?;
    assert_eq!(batch.iter().map(|b| b.counts.requests).sum::<u64>(), 2);
    assert_eq!(batch.iter().map(|b| b.counts.completed).sum::<u64>(), 2);
    assert_eq!(
        batch.iter().map(|b| b.counts.complete_usage).sum::<u64>(),
        2
    );
    assert_eq!(batch.iter().map(|b| b.counts.input_tokens).sum::<u64>(), 20);
    assert_eq!(
        batch.iter().map(|b| b.counts.output_tokens).sum::<u64>(),
        10
    );
    assert_eq!(
        batch
            .iter()
            .map(|b| b.counts.cached_input_tokens)
            .sum::<u64>(),
        8
    );
    assert!(batch.iter().all(|b| b.key_id == "key_admin_exact_id"));
    let bytes = std::fs::read(file)?;
    assert!(!bytes.windows(14).any(|v| v == b"private-output"));
    assert!(!String::from_utf8_lossy(&bytes).contains("private-prompt-canary"));
    assert!(!String::from_utf8_lossy(&bytes).contains("synthetic-key"));
    upstream.abort();
    Ok(())
}
