//! The request body limit at the value documented for a 1M-token context.
//! A body of exactly the limit reaches the router whole; one byte more gets
//! 413 `request_too_large` and never reaches the router.

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode, header},
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig, MAXIMUM_BODY_BYTES_CEILING,
    metrics::GatewayMetrics, protection::ProtectionConfig, router,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

/// The limit `docs/request-body-limit.md` recommends for a 1M-token context.
const ONE_MILLION_TOKEN_LIMIT: usize = 32 * 1024 * 1024;

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, bearer: &str) -> Option<String> {
        (bearer == "valid").then(|| "key".to_owned())
    }
}

struct Audit;

impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

/// A router stand-in that reads the whole body and counts the bytes.
async fn start_upstream(received: Arc<AtomicUsize>) -> String {
    async fn completion(State(received): State<Arc<AtomicUsize>>, body: Bytes) -> Json<Value> {
        received.store(body.len(), Ordering::SeqCst);
        Json(json!({"id":"ok"}))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(completion))
                .layer(DefaultBodyLimit::disable())
                .with_state(received),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    });
    format!("http://{address}")
}

async fn app(maximum_body_bytes: usize, received: Arc<AtomicUsize>) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: start_upstream(received).await,
            maximum_body_bytes,
            upstream_timeout: Duration::from_secs(30),
            protection: ProtectionConfig {
                body_timeout: Duration::from_secs(30),
                ..ProtectionConfig::default()
            },
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        reqwest::Client::new(),
    )
}

/// A valid chat request of exactly `size` bytes.
fn chat_body(size: usize) -> Vec<u8> {
    let prefix = br#"{"model":"deepseek","messages":[{"role":"user","content":""#;
    let suffix = br#""}]}"#;
    let padding = size - prefix.len() - suffix.len();
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    body.resize(prefix.len() + padding, b'x');
    body.extend_from_slice(suffix);
    assert_eq!(body.len(), size);
    body
}

fn request(body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::AUTHORIZATION, "Bearer valid")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| unreachable!())
}

#[test]
fn the_ceiling_admits_the_1m_context_limit() {
    const { assert!(ONE_MILLION_TOKEN_LIMIT <= MAXIMUM_BODY_BYTES_CEILING) };
    assert_eq!(MAXIMUM_BODY_BYTES_CEILING, 64 * 1024 * 1024);
}

#[tokio::test]
async fn a_body_of_exactly_the_limit_reaches_the_router_whole() {
    let received = Arc::new(AtomicUsize::new(0));
    let app = app(ONE_MILLION_TOKEN_LIMIT, received.clone()).await;
    let response = app
        .oneshot(request(chat_body(ONE_MILLION_TOKEN_LIMIT)))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(received.load(Ordering::SeqCst), ONE_MILLION_TOKEN_LIMIT);
}

#[tokio::test]
async fn one_byte_over_the_limit_is_413_and_never_reaches_the_router() {
    let received = Arc::new(AtomicUsize::new(0));
    let app = app(ONE_MILLION_TOKEN_LIMIT, received.clone()).await;
    let response = app
        .oneshot(request(chat_body(ONE_MILLION_TOKEN_LIMIT + 1)))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let bytes = to_bytes(response.into_body(), 4_096)
        .await
        .unwrap_or_else(|_| unreachable!());
    assert!(String::from_utf8_lossy(&bytes).contains("request_too_large"));
    assert_eq!(received.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_body_over_the_ceiling_is_413_whatever_the_setting() {
    let received = Arc::new(AtomicUsize::new(0));
    // A setting above the ceiling cannot pass startup checks; the router
    // layer still bounds it.
    let app = app(MAXIMUM_BODY_BYTES_CEILING * 2, received.clone()).await;
    let response = app
        .oneshot(request(chat_body(MAXIMUM_BODY_BYTES_CEILING + 1)))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(received.load(Ordering::SeqCst), 0);
}
