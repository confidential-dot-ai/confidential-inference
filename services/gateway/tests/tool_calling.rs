use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayAvailability, GatewayConfig,
    UnavailableAttestation,
    metrics::{GatewayMetrics, MetricsSource},
    router,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tower::ServiceExt as _;

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

fn tools_request_body() -> Value {
    json!({
        "model": "deepseek",
        "messages": [{"role": "user", "content": "What is the weather in NYC?"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get the current weather for a location.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "string"}
                        },
                        "required": ["location"]
                    }
                }
            }
        ],
        "tool_choice": "auto"
    })
}

fn tool_calls_response_body() -> Value {
    json!({
        "id": "response-1",
        "object": "chat.completion",
        "model": "deepseek",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"location\":\"NYC\"}"
                    }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 6}
    })
}

/// Spawns a fake upstream that asserts the request it receives carries the
/// exact `tools` and `tool_choice` fields the caller sent, then answers with
/// an `OpenAI`-shaped `tool_calls` completion.
async fn spawn_tool_calling_upstream()
-> (SocketAddr, Arc<Mutex<Option<Value>>>, oneshot::Sender<()>) {
    let captured = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&captured);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new()
                .route(
                    "/v1/chat/completions",
                    post(move |Json(value): Json<Value>| {
                        let observed = Arc::clone(&observed);
                        async move {
                            *observed
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value);
                            Json(tool_calls_response_body())
                        }
                    }),
                )
                .into_make_service(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, captured, stop_tx)
}

/// The exact SSE body the streaming fake upstream sends: a `tool_calls`
/// delta chunk, then a finishing chunk carrying `finish_reason: "tool_calls"`.
fn streaming_tool_calls_sse_body() -> String {
    let delta_chunk = json!({
        "id": "stream-1",
        "object": "chat.completion.chunk",
        "model": "deepseek",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "arguments": "{\"location\":\"NYC\"}"
                    }
                }]
            },
            "finish_reason": Value::Null
        }]
    });
    let finish_chunk = json!({
        "id": "stream-1",
        "object": "chat.completion.chunk",
        "model": "deepseek",
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": "tool_calls"
        }],
        "usage": {"prompt_tokens": 12, "completion_tokens": 6}
    });
    format!("data: {delta_chunk}\n\ndata: {finish_chunk}\n\ndata: [DONE]\n\n")
}

/// Spawns a fake upstream that streams an SSE `tool_calls` delta chunk,
/// followed by a finishing chunk carrying `finish_reason: "tool_calls"`.
async fn spawn_streaming_tool_calling_upstream()
-> (SocketAddr, Arc<Mutex<Option<Value>>>, oneshot::Sender<()>) {
    let captured = Arc::new(Mutex::new(None));
    let observed = Arc::clone(&captured);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new()
                .route(
                    "/v1/chat/completions",
                    post(move |body: Bytes| {
                        let observed = Arc::clone(&observed);
                        async move {
                            let value: Value =
                                serde_json::from_slice(&body).unwrap_or_else(|_| unreachable!());
                            *observed
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value);
                            (
                                [(header::CONTENT_TYPE, "text/event-stream")],
                                streaming_tool_calls_sse_body(),
                            )
                                .into_response()
                        }
                    }),
                )
                .into_make_service(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, captured, stop_tx)
}

fn app(address: SocketAddr, metrics: Arc<GatewayMetrics>) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 1_024 * 1_024,
            upstream_timeout: Duration::from_secs(5),
            protection: confidential_gateway::protection::ProtectionConfig::default(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        metrics,
        GatewayAvailability::default(),
        Arc::new(UnavailableAttestation),
        reqwest::Client::new(),
    )
}

#[tokio::test]
async fn gateway_passes_tools_and_tool_calls_through_unchanged() {
    let (address, captured, stop) = spawn_tool_calling_upstream().await;
    let metrics = Arc::new(GatewayMetrics::new("test"));
    let request_body = tools_request_body();
    let response = app(address, Arc::clone(&metrics))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1_024 * 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    let received: Value = serde_json::from_slice(&body).unwrap_or_else(|_| unreachable!());
    assert_eq!(received, tool_calls_response_body());

    let upstream_saw = captured
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| unreachable!("upstream did not receive a request"));
    assert_eq!(upstream_saw["tools"], request_body["tools"]);
    assert_eq!(upstream_saw["tool_choice"], request_body["tool_choice"]);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("gen_ai_response_finish_reasons"));
    assert!(rendered.contains("reason=\"tool_calls\""));

    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_streams_tool_calls_deltas_through_unchanged() {
    let (address, captured, stop) = spawn_streaming_tool_calling_upstream().await;
    let metrics = Arc::new(GatewayMetrics::new("test"));
    let request_body = tools_request_body();
    let response = app(address, Arc::clone(&metrics))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    let body = to_bytes(response.into_body(), 1_024 * 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    let text = String::from_utf8(body.to_vec()).unwrap_or_else(|_| unreachable!());
    assert_eq!(text, streaming_tool_calls_sse_body());

    let upstream_saw = captured
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .unwrap_or_else(|| unreachable!("upstream did not receive a request"));
    assert_eq!(upstream_saw["tools"], request_body["tools"]);
    assert_eq!(upstream_saw["tool_choice"], request_body["tool_choice"]);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("gen_ai_response_finish_reasons"));
    assert!(rendered.contains("reason=\"tool_calls\""));

    let _ = stop.send(());
}
