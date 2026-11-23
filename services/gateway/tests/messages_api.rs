//! Messages requests use the same upstream, key checks, and usage recorder
//! as Chat Completions. The caller receives the Messages wire format.
#![allow(clippy::unwrap_used)]
use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig,
    metrics::{GatewayMetrics, MetricsSource},
    protection::ProtectionConfig,
    router_with_usage,
    usage::{MAX_PENDING_EVENTS, Model, Outcome, Recorder},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::ServiceExt;

struct Keys;
impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, key: &str) -> Option<String> {
        match key {
            "accepted" => Some("key-1".into()),
            "limited" => Some("key-limited".into()),
            _ => None,
        }
    }
    fn admit(&self, key_id: &str) -> Result<(), confidential_gateway::key_limits::LimitRejection> {
        if key_id == "key-limited" {
            Err(
                confidential_gateway::key_limits::LimitRejection::RateLimited {
                    retry_after_seconds: 17,
                },
            )
        } else {
            Ok(())
        }
    }

    fn verify_revoked_bearer(&self, key: &str) -> Option<String> {
        (key == "revoked").then(|| "key-revoked".into())
    }
}
#[derive(Default)]
struct Audit(Mutex<Vec<AuditEvent>>);
impl AuditSink for Audit {
    fn record(&self, event: AuditEvent) {
        self.0.lock().unwrap().push(event);
    }
}
struct Gateway {
    app: Router,
    received: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    recorder: Arc<Recorder>,
    metrics: Arc<GatewayMetrics>,
    audit: Arc<Audit>,
}
fn completion() -> Value {
    json!({"id":"chatcmpl-test","model":"backend","choices":[{"index":0,"message":{"role":"assistant","content":"日 hello","tool_calls":[{"id":"call-1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"London\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}})
}
fn stream() -> String {
    [
        json!({"model":"backend","choices":[{"index":0,"delta":{"role":"assistant","content":"日 hello"},"finish_reason":null}]}),
        json!({"model":"backend","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call-1","function":{"name":"weather","arguments":""}}]},"finish_reason":null}]}),
        json!({"model":"backend","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"city\":"}}]},"finish_reason":null}]}),
        json!({"model":"backend","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"London\"}"}}]},"finish_reason":"tool_calls"}]}),
        json!({"model":"backend","choices":[],"usage":completion()["usage"]}),
    ].iter().fold(String::new(), |mut result, value| {
        write!(result, "data: {value}\r\n\r\n").unwrap();
        result
    }) + "data: [DONE]\r\n\r\n"
}
async fn gateway() -> Gateway {
    gateway_with_usage(true).await
}

async fn gateway_with_usage(recording: bool) -> Gateway {
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/v1/chat/completions",
                post(move |headers: HeaderMap, Json(body): Json<Value>| {
                    let captured = captured.clone();
                    async move {
                        captured.lock().unwrap().push((headers, body.clone()));
                        if body["messages"][0]["content"] == "worker-error" {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(json!({"error":{"message":"private-worker-input"}})),
                            )
                                .into_response();
                        }
                        if body["messages"][0]["content"] == "invalid-json" {
                            return (
                                [(header::CONTENT_TYPE, "application/json")],
                                "{private-invalid",
                            )
                                .into_response();
                        }
                        if body["messages"][0]["content"] == "invalid-stream" {
                            return (
                                [(header::CONTENT_TYPE, "text/event-stream")],
                                "data: private-invalid\n\n",
                            )
                                .into_response();
                        }
                        if body["stream"] == true {
                            let mut events = stream();
                            if body["messages"][0]["content"] == "interrupted" {
                                events = events.replace("data: [DONE]\r\n\r\n", "");
                            }
                            let chunks = events
                                .as_bytes()
                                .iter()
                                .map(|b| Ok::<_, std::io::Error>(vec![*b]))
                                .collect::<Vec<_>>();
                            (
                                [(header::CONTENT_TYPE, "text/event-stream")],
                                Body::from_stream(futures_util::stream::iter(chunks)),
                            )
                                .into_response()
                        } else {
                            Json(completion()).into_response()
                        }
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let metrics = Arc::new(GatewayMetrics::new("test"));
    let recorder = Recorder::new(
        "gateway-test",
        BTreeMap::from([(
            "public".into(),
            Model {
                served_model: "backend".into(),
                model_revision: "revision".into(),
            },
        )]),
        MAX_PENDING_EVENTS,
        metrics.clone(),
    );
    let audit = Arc::new(Audit::default());
    let app = router_with_usage(
        GatewayConfig {
            catalog_model_ids: vec!["public".into()],
            inference_model_ids: vec!["public".into()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 4096,
            upstream_timeout: Duration::from_secs(5),
            protection: ProtectionConfig::default(),
            unsupported_parameters: Vec::new(),
        },
        Arc::new(Keys),
        audit.clone(),
        metrics.clone(),
        reqwest::Client::new(),
        recording.then(|| recorder.clone()),
    );
    Gateway {
        app,
        received,
        recorder,
        metrics,
        audit,
    }
}
fn payload() -> Value {
    json!({"model":"public","max_tokens":64,"system":[{"type":"text","text":"private-system"}],"messages":[{"role":"user","content":"private-prompt"}]})
}
async fn send(
    g: &Gateway,
    body: &Value,
    headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/messages")
        .header(header::CONTENT_TYPE, "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = g
        .app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    (status, headers, body)
}
fn assert_usage(g: &Gateway) {
    let (_, events) = g.recorder.batch(MAX_PENDING_EVENTS).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].key_id, "key-1");
    assert_eq!(events[0].outcome, Outcome::Completed);
    assert!(events[0].final_usage);
    assert_eq!(events[0].input_tokens, Some(10));
    assert_eq!(events[0].output_tokens, Some(5));
    assert_eq!(events[0].cached_input_tokens, Some(4));
    assert!(!serde_json::to_string(&events).unwrap().contains("private-"));
    let metrics = g.metrics.render_prometheus();
    assert!(metrics.contains("gen_ai_client_token_usage"));
    assert!(!metrics.contains("private-"));
    let audit = g.audit.0.lock().unwrap();
    assert_eq!(audit[0].route, "/v1/messages");
}
#[tokio::test]
async fn sdk_key_json_tools_and_usage() {
    let g = gateway().await;
    let (status, headers, bytes) = send(
        &g,
        &payload(),
        &[
            ("x-api-key", "accepted"),
            ("anthropic-version", "2023-06-01"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(headers.contains_key("x-ci-request-id"));
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["type"], "message");
    assert_eq!(response["model"], "public");
    assert_eq!(
        response["content"][0],
        json!({"type":"text","text":"日 hello"})
    );
    assert_eq!(
        response["content"][1],
        json!({"type":"tool_use","id":"call-1","name":"weather","input":{"city":"London"}})
    );
    assert_eq!(response["stop_reason"], "tool_use");
    assert_eq!(response["usage"]["input_tokens"], 6);
    assert_eq!(response["usage"]["cache_read_input_tokens"], 4);
    let received = g.received.lock().unwrap();
    assert_eq!(
        received[0].1["messages"][0],
        json!({"role":"system","content":"private-system"})
    );
    assert_eq!(received[0].1["max_tokens"], 64);
    assert!(!received[0].0.contains_key("x-api-key"));
    assert!(!received[0].0.contains_key("authorization"));
    drop(received);
    assert_usage(&g);
}
#[tokio::test]
async fn streaming_text_and_tool_arguments_have_messages_events() {
    let g = gateway().await;
    let mut body = payload();
    body["stream"] = json!(true);
    let (status, headers, bytes) = send(&g, &body, &[("authorization", "Bearer accepted")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "text/event-stream");
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("backend"));
    assert!(!text.contains("[DONE]"));
    assert!(!text.contains("event: error"));
    let events = text
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|s| serde_json::from_str::<Value>(s).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(events[0]["type"], "message_start");
    assert_eq!(events[0]["message"]["model"], "public");
    assert!(events.iter().any(|e| e["delta"]["text"] == "日 hello"));
    let arguments = events
        .iter()
        .filter_map(|e| e["delta"]["partial_json"].as_str())
        .collect::<String>();
    assert_eq!(
        serde_json::from_str::<Value>(&arguments).unwrap(),
        json!({"city":"London"})
    );
    assert_eq!(events.last().unwrap()["type"], "message_stop");
    let final_delta = events
        .iter()
        .find(|e| e["type"] == "message_delta")
        .unwrap();
    assert_eq!(final_delta["usage"]["output_tokens"], 5);
    assert_eq!(final_delta["delta"]["stop_reason"], "tool_use");
    assert_eq!(
        g.received.lock().unwrap()[0].1["stream_options"]["include_usage"],
        true
    );
    assert_usage(&g);
}
#[tokio::test]
async fn authentication_model_and_body_limits_apply() {
    let g = gateway().await;
    for headers in [
        vec![],
        vec![("x-api-key", "invalid")],
        vec![("x-api-key", "revoked")],
        vec![
            ("authorization", "Bearer invalid"),
            ("x-api-key", "accepted"),
        ],
    ] {
        let (status, _, bytes) = send(&g, &payload(), &headers).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["type"], "error");
        assert_eq!(error["error"]["type"], "authentication_error");
    }
    let mut body = payload();
    body["model"] = json!("other");
    assert_eq!(
        send(&g, &body, &[("x-api-key", "accepted")]).await.0,
        StatusCode::UNAUTHORIZED
    );
    body = payload();
    body["system"] = json!("x".repeat(8192));
    assert_eq!(
        send(&g, &body, &[("x-api-key", "accepted")]).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(g.received.lock().unwrap().is_empty());
}
#[tokio::test]
async fn unsupported_features_and_worker_errors_are_safe() {
    let g = gateway().await;
    let mut body = payload();
    body["thinking"] = json!({"type":"enabled","budget_tokens":32});
    let (status, _, bytes) = send(&g, &body, &[("x-api-key", "accepted")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let response: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(response["error"]["message"], "unsupported_messages_field");
    assert!(g.received.lock().unwrap().is_empty());
    body = payload();
    body["system"] = json!("worker-error");
    let (status, _, bytes) = send(&g, &body, &[("x-api-key", "accepted")]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !String::from_utf8(bytes)
            .unwrap()
            .contains("private-worker-input")
    );
}
#[tokio::test]
async fn tool_result_round_trip_and_images_use_chat_fields() {
    let g = gateway().await;
    let body = json!({"model":"public","max_tokens":64,"tools":[{"name":"weather","description":"Weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}}}}],"tool_choice":{"type":"tool","name":"weather","disable_parallel_tool_use":true},"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}}]},{"role":"assistant","content":[{"type":"tool_use","id":"call-1","name":"weather","input":{"city":"London"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call-1","content":"rain"},{"type":"text","text":"explain"}]}]});
    assert_eq!(
        send(&g, &body, &[("x-api-key", "accepted")]).await.0,
        StatusCode::OK
    );
    let received = g.received.lock().unwrap();
    let value = &received[0].1;
    assert_eq!(
        value["messages"][0]["content"][0]["image_url"]["url"],
        "data:image/png;base64,aGVsbG8="
    );
    assert_eq!(
        value["messages"][1]["tool_calls"][0]["function"]["arguments"],
        "{\"city\":\"London\"}"
    );
    assert_eq!(
        value["messages"][2],
        json!({"role":"tool","tool_call_id":"call-1","content":"rain"})
    );
    assert_eq!(value["tool_choice"]["function"]["name"], "weather");
    assert_eq!(value["parallel_tool_calls"], false);
}

#[tokio::test]
async fn a_stream_without_done_reports_an_error_and_interrupted_usage() {
    let g = gateway().await;
    let mut body = payload();
    body["system"] = json!("interrupted");
    body["stream"] = json!(true);
    let (status, _, bytes) = send(&g, &body, &[("x-api-key", "accepted")]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("event: error"));
    assert!(!text.contains("event: message_stop"));
    let (_, events) = g.recorder.batch(MAX_PENDING_EVENTS).unwrap();
    assert_eq!(events[0].outcome, Outcome::Interrupted);
}

#[tokio::test]
async fn sdk_keys_have_the_same_rate_limits_and_retry_header() {
    let g = gateway().await;
    let (status, headers, bytes) = send(&g, &payload(), &[("x-api-key", "limited")]).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers[header::RETRY_AFTER], "17");
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["type"], "rate_limit_error");
    assert_eq!(body["error"]["message"], "rate_limit_exceeded");
    assert!(g.received.lock().unwrap().is_empty());
}

#[tokio::test]
async fn browser_sdk_headers_pass_cors_preflight() {
    let g = gateway().await;
    let response = g.app.oneshot(Request::builder().method("OPTIONS").uri("/v1/messages")
        .header("origin", "https://example.com")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "x-api-key,anthropic-version,anthropic-beta,anthropic-dangerous-direct-browser-access")
        .body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let allowed = response.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap();
    for name in [
        "x-api-key",
        "anthropic-version",
        "anthropic-beta",
        "anthropic-dangerous-direct-browser-access",
    ] {
        assert!(allowed.contains(name));
    }
}

#[tokio::test]
async fn malformed_upstream_data_has_the_messages_error_format() {
    let g = gateway().await;
    for streaming in [false, true] {
        let mut body = payload();
        body["system"] = json!(if streaming {
            "invalid-stream"
        } else {
            "invalid-json"
        });
        body["stream"] = json!(streaming);
        let (status, _, bytes) = send(&g, &body, &[("x-api-key", "accepted")]).await;
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("private-invalid"));
        if streaming {
            assert_eq!(status, StatusCode::OK);
            assert!(text.contains("event: error"));
            assert!(!text.contains("event: message_stop"));
        } else {
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            let value: Value = serde_json::from_str(&text).unwrap();
            assert_eq!(value["type"], "error");
            assert_eq!(value["error"]["type"], "api_error");
        }
    }
}

#[tokio::test]
async fn messages_streams_request_usage_even_without_a_recorder() {
    let g = gateway_with_usage(false).await;
    let mut body = payload();
    body["stream"] = json!(true);
    let (status, _, bytes) = send(&g, &body, &[("x-api-key", "accepted")]).await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"output_tokens\":5"));
    assert!(text.contains("event: message_stop"));
    assert_eq!(
        g.received.lock().unwrap()[0].1["stream_options"]["include_usage"],
        true
    );
    assert!(g.recorder.batch(MAX_PENDING_EVENTS).is_none());
}
