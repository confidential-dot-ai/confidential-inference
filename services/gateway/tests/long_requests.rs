//! The limits a 1M-token request meets in the gateway: a first chunk after a
//! long prefill, a stream that stops, and the memory budget of request
//! bodies.

use std::{sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::DefaultBodyLimit,
    http::{Request, StatusCode, header},
    response::Response,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig, metrics::GatewayMetrics,
    protection::ProtectionConfig, request_body, router,
};
use tower::ServiceExt as _;

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, bearer: &str) -> Option<String> {
        bearer
            .strip_prefix("valid-")
            .map(|key| format!("key-{key}"))
    }
}

struct Audit;

impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

/// A router stand-in: it sends the stream headers at once, the first chunk
/// after `first`, and a second chunk `then` later.
async fn start_upstream(first: Duration, then: Duration) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let stream = move |_: Bytes| async move {
        let chunks = async_stream::stream! {
            tokio::time::sleep(first).await;
            yield Ok::<_, std::io::Error>(Bytes::from_static(b"data: {\"choices\":[]}\n\n"));
            tokio::time::sleep(then).await;
            yield Ok(Bytes::from_static(b"data: [DONE]\n\n"));
        };
        Response::builder()
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(chunks))
            .unwrap_or_else(|_| unreachable!())
    };
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(stream))
                .layer(DefaultBodyLimit::disable()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    });
    format!("http://{address}")
}

fn app(upstream: String, protection: ProtectionConfig, maximum_body_bytes: usize) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: upstream,
            maximum_body_bytes,
            upstream_timeout: Duration::from_secs(30),
            protection: ProtectionConfig {
                requests_per_address_per_second: 10_000,
                ..protection
            },
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        reqwest::Client::new(),
    )
}

fn request(key: &str, body: impl Into<Body>, length: Option<usize>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header(header::AUTHORIZATION, format!("Bearer valid-{key}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(length) = length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    builder.body(body.into()).unwrap_or_else(|_| unreachable!())
}

const CHAT: &str =
    r#"{"model":"deepseek","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;

/// The status, and the whole body or the error that ended it.
async fn finish(app: Router, request: Request<Body>) -> (StatusCode, Result<String, String>) {
    let response = app
        .oneshot(request)
        .await
        .unwrap_or_else(|_| unreachable!());
    let status = response.status();
    let body = to_bytes(response.into_body(), 1 << 20)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|error| error.to_string());
    (status, body)
}

#[tokio::test]
async fn a_long_prefill_waits_for_the_first_token_timeout_not_the_idle_timeout() {
    let upstream = start_upstream(Duration::from_millis(1_500), Duration::ZERO).await;
    let app = app(
        upstream,
        ProtectionConfig {
            first_token_timeout: Duration::from_secs(5),
            stream_idle_timeout: Duration::from_secs(1),
            ..ProtectionConfig::default()
        },
        1_024,
    );
    let (status, body) = finish(app, request("a", CHAT, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_ok_and(|text| text.contains("[DONE]")));
}

#[tokio::test]
async fn the_first_token_timeout_ends_a_stream_without_a_first_chunk() {
    let upstream = start_upstream(Duration::from_secs(10), Duration::ZERO).await;
    let app = app(
        upstream,
        ProtectionConfig {
            first_token_timeout: Duration::from_secs(1),
            stream_idle_timeout: Duration::from_secs(5),
            ..ProtectionConfig::default()
        },
        1_024,
    );
    let started = std::time::Instant::now();
    let (status, body) = finish(app, request("a", CHAT, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_err());
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test]
async fn after_the_first_chunk_the_idle_timeout_applies() {
    let upstream = start_upstream(Duration::ZERO, Duration::from_secs(10)).await;
    let app = app(
        upstream,
        ProtectionConfig {
            first_token_timeout: Duration::from_secs(30),
            stream_idle_timeout: Duration::from_secs(1),
            ..ProtectionConfig::default()
        },
        1_024,
    );
    let started = std::time::Instant::now();
    let (_, body) = finish(app, request("a", CHAT, None)).await;
    assert!(body.is_err());
    assert!(started.elapsed() < Duration::from_secs(4));
}

/// A chat body of `size` bytes, mostly one string.
fn chat_body(size: usize) -> Vec<u8> {
    let prefix = br#"{"model":"deepseek","stream":true,"messages":[{"role":"user","content":""#;
    let suffix = br#""}]}"#;
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    body.resize(size - suffix.len(), b'x');
    body.extend_from_slice(suffix);
    body
}

#[tokio::test]
async fn bodies_wait_for_the_memory_budget_then_get_429() {
    const LIMIT: usize = 1 << 20;
    // Each body of the limit reserves `read_cost` before its read: the
    // minimum budget holds one of them, not two.
    let protection = ProtectionConfig {
        body_memory_bytes: request_body::minimum_budget(LIMIT),
        queue_timeout: Duration::from_millis(500),
        ..ProtectionConfig::default()
    };
    let app = app(
        start_upstream(Duration::ZERO, Duration::ZERO).await,
        protection,
        LIMIT,
    );
    // A body that never ends keeps its share of the budget.
    let (sender, receiver) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    let body = Body::from_stream(tokio_stream(receiver));
    let stalled = tokio::spawn(app.clone().oneshot(request("a", body, Some(LIMIT))));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, body) = finish(app.clone(), request("c", chat_body(LIMIT), Some(LIMIT))).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(body.is_ok_and(|text| text.contains("body_memory_capacity")));
    // The stalled body returns its share when it fails.
    drop(sender);
    let _ = stalled.await;
    let (status, _) = finish(app, request("c", chat_body(LIMIT), Some(LIMIT))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_body_of_many_small_items_pays_for_its_parsed_value() {
    const LIMIT: usize = 1 << 20;
    let protection = ProtectionConfig {
        body_memory_bytes: request_body::minimum_budget(LIMIT),
        ..ProtectionConfig::default()
    };
    let app = app(
        start_upstream(Duration::ZERO, Duration::ZERO).await,
        protection,
        LIMIT,
    );
    // 1 MiB of `0,` parses to more than 16 MiB of values: more than the
    // whole budget.
    let mut body =
        br#"{"model":"deepseek","stream":true,"messages":[{"role":"user","content":"hi"}],"x":["#
            .to_vec();
    while body.len() < LIMIT - 8 {
        body.extend_from_slice(b"0,");
    }
    body.extend_from_slice(b"0]}");
    let length = body.len();
    let (status, body) = finish(app.clone(), request("a", body, Some(length))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(body.is_ok_and(|text| text.contains("request_too_large")));
    // A text body of the same size passes.
    let (status, _) = finish(app, request("a", chat_body(LIMIT), Some(LIMIT))).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_declared_length_above_the_limit_is_413_before_the_read() {
    let app = app(
        start_upstream(Duration::ZERO, Duration::ZERO).await,
        ProtectionConfig::default(),
        1_024,
    );
    let (status, _) = finish(app, request("a", Body::empty(), Some(1_025))).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

fn tokio_stream(
    mut receiver: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
) -> impl futures_util::Stream<Item = Result<Bytes, std::io::Error>> {
    async_stream::stream! {
        while let Some(item) = receiver.recv().await {
            yield item;
        }
    }
}
