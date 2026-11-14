//! `POST /v1/responses` against a fake upstream that answers like the `SGLang`
//! Responses API: authentication, the stateless request rules, the body
//! limit, model rewriting, and usage accounting for JSON and event streams.
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig,
    metrics::{GatewayMetrics, MetricsSource},
    protection::ProtectionConfig,
    router_with_usage,
    usage::{Event, MAX_PENDING_EVENTS, Model, Outcome, Recorder},
};
use serde_json::{Value, json};
use tower::ServiceExt;

const PUBLIC_MODEL: &str = "model-a";
const BACKEND_MODEL: &str = "backend-a";

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, value: &str) -> Option<String> {
        (value == "accepted").then(|| "key_record_1".to_owned())
    }

    fn verify_revoked_bearer(&self, value: &str) -> Option<String> {
        (value == "revoked").then(|| "key_record_revoked".to_owned())
    }
}

#[derive(Default)]
struct CapturedAudit(Mutex<Vec<AuditEvent>>);

impl AuditSink for CapturedAudit {
    fn record(&self, event: AuditEvent) {
        self.0.lock().unwrap_or_else(|_| unreachable!()).push(event);
    }
}

fn completed_response(status: &str) -> Value {
    json!({
        "id": "resp_1",
        "object": "response",
        "created_at": 0,
        "model": BACKEND_MODEL,
        "status": status,
        "store": false,
        "output": [{
            "type": "message",
            "id": "msg_1",
            "role": "assistant",
            "status": "completed",
            "content": [{"type": "output_text", "text": "private-output", "annotations": []}]
        }],
        "usage": {
            "input_tokens": 10,
            "input_tokens_details": {"cached_tokens": 4, "cache_write_tokens": 0},
            "output_tokens": 5,
            "output_tokens_details": {"reasoning_tokens": 2},
            "total_tokens": 15
        }
    })
}

fn event(kind: &str, fields: &Value) -> String {
    let mut payload = json!({"type": kind});
    for (key, value) in fields.as_object().unwrap_or_else(|| unreachable!()) {
        payload[key] = value.clone();
    }
    format!("event: {kind}\ndata: {payload}\n\n")
}

fn event_stream() -> String {
    let mut created = completed_response("in_progress");
    created["output"] = json!([]);
    created["usage"] = Value::Null;
    [
        event(
            "response.created",
            &json!({"sequence_number": 0, "response": created}),
        ),
        event(
            "response.output_text.delta",
            &json!({"sequence_number": 1, "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "private-"}),
        ),
        event(
            "response.output_text.delta",
            &json!({"sequence_number": 2, "item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": "output"}),
        ),
        event(
            "response.completed",
            &json!({"sequence_number": 3, "response": completed_response("completed")}),
        ),
    ]
    .concat()
}

/// A fake `SGLang` `/v1/responses`. It records each body it receives.
async fn start_upstream() -> (SocketAddr, Arc<Mutex<Vec<Value>>>) {
    let received = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&received);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    tokio::spawn(async move {
        let app = Router::new().route(
            "/v1/responses",
            post(move |Json(payload): Json<Value>| {
                let captured = Arc::clone(&captured);
                async move {
                    let streaming = payload["stream"] == true;
                    captured
                        .lock()
                        .unwrap_or_else(|_| unreachable!())
                        .push(payload);
                    if streaming {
                        (
                            [(header::CONTENT_TYPE, "text/event-stream")],
                            Body::from(Bytes::from(event_stream())),
                        )
                            .into_response()
                    } else {
                        Json(completed_response("completed")).into_response()
                    }
                }
            }),
        );
        axum::serve(listener, app).await
    });
    (address, received)
}

struct Gateway {
    app: Router,
    recorder: Arc<Recorder>,
    metrics: Arc<GatewayMetrics>,
    audit: Arc<CapturedAudit>,
    received: Arc<Mutex<Vec<Value>>>,
}

async fn gateway() -> Gateway {
    let (address, received) = start_upstream().await;
    let metrics = Arc::new(GatewayMetrics::new("test"));
    let models = BTreeMap::from([(
        PUBLIC_MODEL.to_owned(),
        Model {
            served_model: BACKEND_MODEL.into(),
            model_revision: "revision-1".into(),
        },
    )]);
    let recorder = Recorder::new("gateway-test", models, MAX_PENDING_EVENTS, metrics.clone());
    let audit = Arc::new(CapturedAudit::default());
    let app = router_with_usage(
        GatewayConfig {
            catalog_model_ids: vec![PUBLIC_MODEL.into()],
            inference_model_ids: vec![PUBLIC_MODEL.into()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 4096,
            upstream_timeout: Duration::from_secs(5),
            protection: ProtectionConfig::default(),
        },
        Arc::new(Keys),
        audit.clone(),
        metrics.clone(),
        reqwest::Client::new(),
        Some(recorder.clone()),
    );
    Gateway {
        app,
        recorder,
        metrics,
        audit,
        received,
    }
}

fn request(authorization: Option<&str>, body: &Value) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(value) = authorization {
        request = request.header(header::AUTHORIZATION, value);
    }
    request
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| unreachable!())
}

async fn send(gateway: &Gateway, authorization: Option<&str>, body: &Value) -> (StatusCode, Bytes) {
    let response = gateway
        .app
        .clone()
        .oneshot(request(authorization, body))
        .await
        .unwrap_or_else(|_| unreachable!());
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_else(|_| unreachable!());
    (status, body)
}

fn usage_events(recorder: &Recorder) -> Vec<Event> {
    recorder
        .batch(MAX_PENDING_EVENTS)
        .map(|(_, events)| events)
        .unwrap_or_default()
}

fn assert_accounted(event: &Event) {
    assert_eq!(event.key_id, "key_record_1");
    assert_eq!(event.requested_model, PUBLIC_MODEL);
    assert_eq!(event.outcome, Outcome::Completed);
    assert!(event.final_usage);
    assert_eq!(event.input_tokens, Some(10));
    assert_eq!(event.output_tokens, Some(5));
    assert_eq!(event.cached_input_tokens, Some(4));
    assert_eq!(event.reasoning_tokens, Some(2));
}

#[tokio::test]
async fn a_json_response_is_proxied_rewritten_and_accounted() {
    let gateway = gateway().await;
    let (status, body) = send(
        &gateway,
        Some("Bearer accepted"),
        &json!({"model": PUBLIC_MODEL, "input": "private-prompt"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&body).unwrap_or_default();
    assert_eq!(body["model"], PUBLIC_MODEL);
    assert_eq!(body["output"][0]["content"][0]["text"], "private-output");
    assert_eq!(body["usage"]["input_tokens"], 10);

    // The gateway tells the upstream not to store the response, and adds no
    // chat-completions field.
    let received = gateway
        .received
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .clone();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0]["store"], false);
    assert_eq!(received[0]["input"], "private-prompt");
    assert_eq!(received[0]["stream"], false);
    assert!(received[0].get("stream_options").is_none());

    let events = usage_events(&gateway.recorder);
    assert_eq!(events.len(), 1);
    assert_accounted(&events[0]);
    let text = serde_json::to_string(&events).unwrap_or_default();
    assert!(!text.contains("private-"));

    let rendered = gateway.metrics.render_prometheus();
    assert!(rendered.contains("gen_ai_client_token_usage"), "{rendered}");
    assert!(rendered.contains("key_id=\"key_record_1\""), "{rendered}");
    assert!(
        rendered.contains("gen_ai_usage_cache_read_input_tokens"),
        "{rendered}"
    );
    assert!(rendered.contains("reason=\"stop\""), "{rendered}");
    assert!(!rendered.contains("private-"));

    let audit = gateway.audit.0.lock().unwrap_or_else(|_| unreachable!());
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].route, "/v1/responses");
    assert_eq!(audit[0].status, 200);
    assert_eq!(audit[0].key_id.as_deref(), Some("key_record_1"));
}

#[tokio::test]
async fn an_event_stream_is_relayed_and_accounted_from_response_completed() {
    let gateway = gateway().await;
    let (status, body) = send(
        &gateway,
        Some("Bearer accepted"),
        &json!({"model": PUBLIC_MODEL, "input": [{"role": "user", "content": "private-prompt"}], "stream": true}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = String::from_utf8(body.to_vec()).unwrap_or_default();
    assert!(text.starts_with("event: response.created\n"), "{text}");
    assert!(text.contains("\"delta\":\"private-\""), "{text}");
    assert!(text.contains("event: response.completed\n"), "{text}");
    assert!(!text.contains(BACKEND_MODEL), "{text}");
    assert_eq!(
        text.matches(&format!("\"model\":\"{PUBLIC_MODEL}\""))
            .count(),
        2,
        "{text}"
    );
    // The caller sees its usage in the terminal event; no `[DONE]` is added.
    assert!(text.contains("\"output_tokens\":5"), "{text}");
    assert!(!text.contains("[DONE]"), "{text}");

    let received = gateway
        .received
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .clone();
    assert_eq!(received[0]["store"], false);
    assert!(received[0].get("stream_options").is_none());

    let events = usage_events(&gateway.recorder);
    assert_eq!(events.len(), 1);
    assert_accounted(&events[0]);

    let rendered = gateway.metrics.render_prometheus();
    assert!(
        rendered.contains("gen_ai_server_time_to_first_token_count"),
        "{rendered}"
    );
    assert!(rendered.contains("gen_ai_client_token_usage"), "{rendered}");
    assert!(!rendered.contains("private-"));
}

#[tokio::test]
async fn a_missing_invalid_or_revoked_key_is_rejected_before_the_upstream() {
    let gateway = gateway().await;
    let body = json!({"model": PUBLIC_MODEL, "input": "hello"});
    for authorization in [
        None,
        Some("Bearer invalid"),
        Some("Bearer revoked"),
        Some("Basic accepted"),
    ] {
        let (status, body) = send(&gateway, authorization, &body).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{authorization:?} {body:?}"
        );
        let body: Value = serde_json::from_slice(&body).unwrap_or_default();
        assert_eq!(body["error"]["code"], "invalid_api_key");
    }
    assert!(
        gateway
            .received
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .is_empty()
    );
    assert!(usage_events(&gateway.recorder).is_empty());
}

#[tokio::test]
async fn a_request_for_server_side_state_is_rejected() {
    let gateway = gateway().await;
    for (field, value) in [
        ("previous_response_id", json!("resp_earlier")),
        ("conversation", json!("conv_1")),
        ("conversation", json!({"id": "conv_1"})),
        ("store", json!(true)),
        ("background", json!(true)),
        ("store", json!("yes")),
    ] {
        let mut body = json!({"model": PUBLIC_MODEL, "input": "hello"});
        body[field] = value.clone();
        let (status, response) = send(&gateway, Some("Bearer accepted"), &body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{field}: {value}");
        let response: Value = serde_json::from_slice(&response).unwrap_or_default();
        assert_eq!(
            response["error"]["code"], "stateful_responses_not_supported",
            "{field}"
        );
        assert!(
            response["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains(field),
            "{response}"
        );
    }
    assert!(
        gateway
            .received
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .is_empty()
    );
    assert!(usage_events(&gateway.recorder).is_empty());

    // Explicit stateless values pass.
    let (status, _) = send(
        &gateway,
        Some("Bearer accepted"),
        &json!({"model": PUBLIC_MODEL, "input": "hello", "store": false, "background": false, "previous_response_id": null}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_body_limit_and_model_check_apply() {
    let gateway = gateway().await;
    let (status, body) = send(
        &gateway,
        Some("Bearer accepted"),
        &json!({"model": PUBLIC_MODEL, "input": "x".repeat(8192)}),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = serde_json::from_slice(&body).unwrap_or_default();
    assert_eq!(body["error"]["code"], "request_too_large");

    let (status, body) = send(
        &gateway,
        Some("Bearer accepted"),
        &json!({"model": "other", "input": "hello"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(&body).unwrap_or_default();
    assert_eq!(body["error"]["code"], "model_not_authorized");
    assert!(
        gateway
            .received
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .is_empty()
    );
}
