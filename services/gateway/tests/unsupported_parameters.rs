//! `unsupportedParameters` of the gateway settings: a request that sets a
//! listed parameter to a refused value gets 400 `unsupported_parameter`
//! before it reaches the router, on every inference API.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig,
    metrics::{GatewayMetrics, MetricsSource},
    router,
    settings::UnsupportedParameter,
};
use serde_json::{Value, json};
use tower::ServiceExt;

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, value: &str) -> Option<String> {
        (value == "accepted").then(|| "key_record_1".to_owned())
    }
}

struct Audit;

impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

/// The parameters of recipe deepseek-v41-flash-262k-4xb200.
fn parameters() -> Vec<UnsupportedParameter> {
    serde_json::from_value(json!([
        {"name":"n","allowed":[1]},
        {"name":"best_of","allowed":[1]},
        {"name":"min_p","allowed":[0]},
        {"name":"logprobs","allowed":[false]},
        {"name":"top_logprobs","allowed":[0]},
    ]))
    .unwrap_or_else(|_| unreachable!())
}

async fn spawn_upstream(hits: Arc<AtomicUsize>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let answer = move |Json(value): Json<Value>| {
        let hits = Arc::clone(&hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Json(json!({
                "id":"response-1","object":"chat.completion","model":value["model"],
                "choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"text":"ok","finish_reason":"stop"}],
                "output":[],"status":"completed",
            }))
        }
    };
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(answer.clone()))
                .route("/v1/completions", post(answer.clone()))
                .route("/v1/responses", post(answer)),
        )
        .await;
    });
    address
}

struct Gateway {
    app: Router,
    hits: Arc<AtomicUsize>,
    metrics: Arc<GatewayMetrics>,
}

async fn gateway() -> Gateway {
    let hits = Arc::new(AtomicUsize::new(0));
    let address = spawn_upstream(hits.clone()).await;
    let metrics = Arc::new(GatewayMetrics::new("test"));
    let app = router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 1_024 * 1_024,
            upstream_timeout: Duration::from_secs(5),
            protection: confidential_gateway::protection::ProtectionConfig::default(),
            unsupported_parameters: parameters(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        metrics.clone(),
        reqwest::Client::new(),
    );
    Gateway { app, hits, metrics }
}

async fn send(gateway: &Gateway, route: &str, body: &Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(route)
        .header(header::AUTHORIZATION, "Bearer accepted")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| unreachable!());
    let response = gateway
        .app
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|_| unreachable!());
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_else(|_| unreachable!());
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn with(base: &Value, extra: &Value) -> Value {
    let mut body = base.clone();
    for (key, value) in extra.as_object().unwrap_or_else(|| unreachable!()) {
        body[key] = value.clone();
    }
    body
}

fn chat() -> Value {
    json!({"model":"deepseek","messages":[{"role":"user","content":"PRIVATE_PROMPT"}]})
}

fn completions() -> Value {
    json!({"model":"deepseek","prompt":"PRIVATE_PROMPT"})
}

fn responses() -> Value {
    json!({"model":"deepseek","input":"PRIVATE_PROMPT"})
}

#[tokio::test]
async fn refused_values_get_400_before_the_router() {
    let gateway = gateway().await;
    let cases = [
        ("/v1/chat/completions", chat(), json!({"n":2}), "n"),
        (
            "/v1/chat/completions",
            chat(),
            json!({"min_p":0.05}),
            "min_p",
        ),
        (
            "/v1/chat/completions",
            chat(),
            json!({"logprobs":true}),
            "logprobs",
        ),
        (
            "/v1/chat/completions",
            chat(),
            json!({"top_logprobs":5}),
            "top_logprobs",
        ),
        ("/v1/completions", completions(), json!({"n":4}), "n"),
        (
            "/v1/completions",
            completions(),
            json!({"best_of":2}),
            "best_of",
        ),
        // A completions `logprobs` is a count; 0 still returns logprobs.
        (
            "/v1/completions",
            completions(),
            json!({"logprobs":0}),
            "logprobs",
        ),
        (
            "/v1/completions",
            completions(),
            json!({"min_p":"0.1"}),
            "min_p",
        ),
        (
            "/v1/responses",
            responses(),
            json!({"top_logprobs":3}),
            "top_logprobs",
        ),
        ("/v1/responses", responses(), json!({"min_p":0.2}), "min_p"),
        (
            "/v1/responses",
            responses(),
            json!({"include":["message.output_text.logprobs"]}),
            "logprobs",
        ),
    ];
    for (route, base, extra, name) in &cases {
        let (status, body) = send(&gateway, route, &with(base, extra)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{route} {extra}");
        assert_eq!(
            body["error"]["code"], "unsupported_parameter",
            "{route} {extra}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(&format!("`{name}`")),
            "{route} {extra}: {message}"
        );
        // The answer names the parameter, never the request's content.
        assert!(!body.to_string().contains("PRIVATE_PROMPT"));
    }
    assert_eq!(gateway.hits.load(Ordering::SeqCst), 0);
    let metrics = gateway.metrics.render_prometheus();
    let line = metrics
        .lines()
        .find(|line| line.contains("unsupported_parameter") && !line.starts_with('#'))
        .unwrap_or_else(|| unreachable!("no unsupported_parameter rejection: {metrics}"));
    assert!(line.ends_with(&format!(" {}", cases.len())), "{line}");
}

#[tokio::test]
async fn absent_null_and_allowed_values_pass() {
    let gateway = gateway().await;
    let cases = [
        ("/v1/chat/completions", chat(), json!({})),
        (
            "/v1/chat/completions",
            chat(),
            json!({"n":1,"min_p":0,"logprobs":false,"top_logprobs":0}),
        ),
        (
            "/v1/chat/completions",
            chat(),
            json!({"n":1.0,"min_p":0.0,"logprobs":null,"top_logprobs":null}),
        ),
        (
            "/v1/completions",
            completions(),
            json!({"n":1,"best_of":1,"logprobs":null}),
        ),
        (
            "/v1/responses",
            responses(),
            json!({"top_logprobs":0,"include":["reasoning.encrypted_content"]}),
        ),
    ];
    for (route, base, extra) in &cases {
        let (status, body) = send(&gateway, route, &with(base, extra)).await;
        assert_eq!(status, StatusCode::OK, "{route} {extra}: {body}");
    }
    assert_eq!(gateway.hits.load(Ordering::SeqCst), cases.len());
}

#[tokio::test]
async fn messages_never_forward_a_listed_parameter() {
    // The Messages API refuses fields it cannot translate first, and its
    // translation sets none of the listed parameters.
    let gateway = gateway().await;
    let base =
        json!({"model":"deepseek","max_tokens":16,"messages":[{"role":"user","content":"hi"}]});
    let (status, body) = send(&gateway, "/v1/messages", &with(&base, &json!({"n":2}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_ne!(body.to_string(), "null");
    let (status, _) = send(&gateway, "/v1/messages", &base).await;
    assert_eq!(status, StatusCode::OK);
}
