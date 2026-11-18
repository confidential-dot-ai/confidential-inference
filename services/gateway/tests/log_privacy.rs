//! Request content, client addresses and raw key record IDs never reach the
//! gateway logs, and an upstream error text never reaches the caller.
//!
//! Each test captures every log line that the production log layer
//! (`log_privacy::stdout_layer`) writes, with `RUST_LOG=trace` for all other
//! targets, so the HTTP libraries' debug output is in scope too. Every
//! captured line must be a JSON object whose message the node log agent and
//! the collector keep: a listed fixed message or the audit record.

use std::{
    io::Write,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, GatewayConfig, TracingAuditSink, log_privacy, metrics::GatewayMetrics, router,
};
use serde_json::Value;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

const CANARY: &str = "CANARY_7f3a91_PRIVATE_PROMPT_TEXT";
const CLIENT_ADDRESS: &str = "198.51.100.77";
const KEY_RECORD: &str = "key_record_privacy_1";
const SECRET: [u8; 32] = [42; 32];
/// The audit record pattern of the node log agent and the collector. Keep it
/// equal to the chart's pattern.
const AUDIT_RECORD: &str = r#"^[{]"event":"gateway_request_completed","key_ref":("kp_[0-9a-f]{24}"|null),"request_id":"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}","route":"/v1/(models|chat/completions|completions|responses)","status":[1-5][0-9][0-9][}]$"#;
/// The chart files that can hold the gateway message list, relative to this
/// crate. A file that does not exist is skipped.
const MESSAGE_LIST_FILES: &[&str] = &[
    "../../helm/confidential-inference/templates/_log-policy.tpl",
    "../../helm/confidential-inference/templates/telemetry-collector.yaml",
];

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, value: &str) -> Option<String> {
        (value == "accepted").then(|| KEY_RECORD.to_owned())
    }
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(|_| unreachable!())).into_owned()
    }
}

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The gateway's log setup with `RUST_LOG=trace`: every line the production
/// log layer writes goes into `captured`.
fn capture() -> (Captured, tracing::subscriber::DefaultGuard) {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("trace"))
        .with(log_privacy::stdout_layer(move || writer.clone()));
    (captured, tracing::subscriber::set_default(subscriber))
}

/// The text of the chart files that list the gateway messages. A listed
/// message appears in them as a double-quoted string, `"text"`.
fn message_list() -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let text: String = MESSAGE_LIST_FILES
        .iter()
        .filter_map(|file| std::fs::read_to_string(root.join(file)).ok())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !text.is_empty(),
        "no chart file with the gateway message list"
    );
    text
}

fn is_listed(list: &str, message: &str) -> bool {
    !message.contains('"') && list.contains(&format!("\"{message}\""))
}

/// Every line is one JSON object, and its message is a listed fixed message
/// or the audit record, so the node log agent keeps it.
fn assert_reviewed(logs: &str) {
    let list = message_list();
    let audit = regex::Regex::new(AUDIT_RECORD).unwrap_or_else(|_| unreachable!());
    for line in logs.lines() {
        let value: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("a log line is not JSON ({error}): {line}"));
        let object = value
            .as_object()
            .unwrap_or_else(|| panic!("a log line is not a JSON object: {line}"));
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("a log line has no message: {line}"));
        assert!(
            object.get("level").and_then(Value::as_str).is_some(),
            "a log line has no level: {line}"
        );
        assert!(
            is_listed(&list, message) || audit.is_match(message),
            "the node log agent would drop this message: {line}"
        );
    }
}

/// An inference server that answers every request with `status` and an
/// error body that quotes the request, like a validation error does.
async fn spawn_failing_upstream(
    status: StatusCode,
    retry_after: Option<&'static str>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let handler = move |body: Bytes| async move {
        let echoed = String::from_utf8_lossy(&body).into_owned();
        let mut response = (
            status,
            [(header::CONTENT_TYPE, "application/json")],
            serde_json::json!({
                "object": "error",
                "message": format!("invalid request {CANARY}: {echoed}"),
                "detail": [{"type": "value_error", "input": echoed}],
            })
            .to_string(),
        )
            .into_response();
        if let Some(value) = retry_after {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, header::HeaderValue::from_static(value));
        }
        response
    };
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(handler))
                .route("/v1/completions", post(handler)),
        )
        .await;
    });
    address
}

fn gateway(address: SocketAddr) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 64 * 1_024,
            upstream_timeout: Duration::from_secs(5),
            protection: confidential_gateway::protection::ProtectionConfig {
                trusted_proxy_cidrs: vec!["10.0.0.0/8".parse().unwrap_or_else(|_| unreachable!())],
                ..confidential_gateway::protection::ProtectionConfig::default()
            },
        },
        Arc::new(Keys),
        Arc::new(TracingAuditSink::new(
            log_privacy::KeyPseudonyms::from_secret(&SECRET),
        )),
        Arc::new(GatewayMetrics::new("test")),
        reqwest::Client::new(),
    )
}

/// One inference request through a trusted proxy, so the gateway takes the
/// client address from `x-forwarded-for` and uses it for its rate limits.
fn inference(route: &str, body: impl Into<Body>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(route)
        .header(header::AUTHORIZATION, "Bearer accepted")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", CLIENT_ADDRESS)
        .header("x-real-ip", CLIENT_ADDRESS)
        .header(header::USER_AGENT, format!("client/{CANARY}"))
        .body(body.into())
        .unwrap_or_else(|_| unreachable!());
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(SocketAddr::from((
            [10, 0, 0, 9],
            40_000,
        ))));
    request
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, header::HeaderMap, String) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .unwrap_or_else(|_| unreachable!());
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap_or_else(|_| unreachable!());
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn assert_private(logs: &str) {
    for secret in [CANARY, CLIENT_ADDRESS, KEY_RECORD, "Bearer accepted"] {
        assert!(!logs.contains(secret), "the logs carry {secret}:\n{logs}");
    }
    assert_reviewed(logs);
}

#[tokio::test]
async fn upstream_error_bodies_reach_neither_logs_nor_callers() {
    let (captured, _guard) = capture();
    for (status, retry_after, code) in [
        (StatusCode::BAD_REQUEST, None, "invalid_request"),
        (StatusCode::UNPROCESSABLE_ENTITY, None, "invalid_request"),
        (StatusCode::TOO_MANY_REQUESTS, Some("7"), "rate_limited"),
        (StatusCode::INTERNAL_SERVER_ERROR, None, "inference_error"),
    ] {
        let app = gateway(spawn_failing_upstream(status, retry_after).await);
        for route in ["/v1/chat/completions", "/v1/completions"] {
            let request = serde_json::json!({
                "model": "deepseek",
                "messages": [{"role": "user", "content": CANARY}],
                "prompt": CANARY,
            });
            let (answered, headers, body) = send(&app, inference(route, request.to_string())).await;
            assert_eq!(answered, status);
            assert!(
                !body.contains(CANARY),
                "the response carries the upstream text: {body}"
            );
            assert!(!body.contains("value_error"), "{body}");
            let value: Value = serde_json::from_str(&body).unwrap_or_default();
            assert_eq!(value["error"]["code"], code, "{body}");
            assert_eq!(
                headers
                    .get(header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok()),
                retry_after
            );
        }
    }
    let logs = captured.text();
    assert_private(&logs);
    // The audit record is there, with a key pseudonym instead of the key ID.
    let pseudonym = log_privacy::KeyPseudonyms::from_secret(&SECRET).pseudonym(KEY_RECORD);
    assert!(logs.contains("gateway_request_completed"), "{logs}");
    assert!(logs.contains(&pseudonym), "{logs}");
    assert!(
        logs.lines().any(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_default();
            value["message"]
                .as_str()
                .is_some_and(|message| message.contains(r#""status":422"#))
        }),
        "{logs}"
    );
}

#[tokio::test]
async fn malformed_requests_are_not_echoed_or_logged() {
    let (captured, _guard) = capture();
    let app = gateway(spawn_failing_upstream(StatusCode::BAD_REQUEST, None).await);
    let cases = [
        // Not JSON.
        (
            format!(r#"{{"model":"deepseek","messages":[{CANARY}"#),
            StatusCode::BAD_REQUEST,
        ),
        // JSON that a strict parser would refuse with a quote of the input.
        (
            format!(r#"{{"model":"deepseek","max_tokens":"{CANARY}""#),
            StatusCode::BAD_REQUEST,
        ),
        // Valid JSON with no model.
        (
            format!(r#"{{"messages":"{CANARY}"}}"#),
            StatusCode::BAD_REQUEST,
        ),
        // A model name that is the content.
        (
            format!(r#"{{"model":"{CANARY}"}}"#),
            StatusCode::UNAUTHORIZED,
        ),
        // Invalid UTF-8 around the content.
        (
            format!("{{\"model\":\"deepseek\",\"x\":\"\u{fffd}{CANARY}"),
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (body, status) in cases {
        let (answered, _, response) = send(&app, inference("/v1/chat/completions", body)).await;
        assert_eq!(answered, status, "{response}");
        assert!(
            !response.contains(CANARY),
            "the response echoes the request: {response}"
        );
    }
    // A body over the limit, and forwarding headers the gateway refuses.
    let large = format!(
        r#"{{"model":"deepseek","prompt":"{}"}}"#,
        CANARY.repeat(4_096)
    );
    let (answered, _, response) = send(&app, inference("/v1/chat/completions", large)).await;
    assert_eq!(answered, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!response.contains(CANARY));
    let mut forwarded = inference("/v1/chat/completions", r#"{"model":"deepseek"}"#);
    forwarded.headers_mut().insert(
        "x-forwarded-for",
        header::HeaderValue::from_static("198.51.100.77, 10.0.0.1"),
    );
    let (answered, _, response) = send(&app, forwarded).await;
    assert_eq!(answered, StatusCode::BAD_REQUEST);
    assert!(!response.contains(CLIENT_ADDRESS));
    assert_private(&captured.text());
}

#[tokio::test]
async fn a_successful_exchange_logs_no_content() {
    async fn backend(body: Bytes) -> impl IntoResponse {
        let request: Value = serde_json::from_slice(&body).unwrap_or_default();
        axum::Json(serde_json::json!({
            "model": request["model"],
            "choices": [{"message": {"content": format!("answer {CANARY}")}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 2},
        }))
    }
    let (captured, _guard) = capture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route("/v1/chat/completions", post(backend)),
        )
        .await;
    });
    let request =
        serde_json::json!({"model": "deepseek", "messages": [{"role": "user", "content": CANARY}]});
    let (status, _, body) = send(
        &gateway(address),
        inference("/v1/chat/completions", request.to_string()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The answer itself goes to the caller, as it must.
    assert!(body.contains(CANARY));
    assert_private(&captured.text());
}

/// The log messages of one source file: the last string literal of each
/// `tracing` macro call. Comments are not parsed; the sources have no
/// `tracing::` call inside a comment.
fn messages(source: &str) -> Vec<String> {
    let mut found = Vec::new();
    for level in ["trace", "debug", "info", "warn", "error"] {
        let marker = format!("tracing::{level}!(");
        let mut rest = source;
        while let Some(start) = rest.find(&marker) {
            rest = &rest[start + marker.len()..];
            let (mut depth, mut literal, mut last, mut current) =
                (1_i32, false, None, String::new());
            let mut characters = rest.chars();
            while let Some(character) = characters.next() {
                if literal {
                    match character {
                        '\\' => {
                            current.push(character);
                            current.extend(characters.next());
                        }
                        '"' => {
                            literal = false;
                            last = Some(std::mem::take(&mut current));
                        }
                        _ => current.push(character),
                    }
                    continue;
                }
                match character {
                    '"' => literal = true,
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            found.extend(last);
        }
    }
    found
}

/// The node log agent and the collector keep a gateway log message only when
/// it is one of the messages the chart lists, or the audit record. Every
/// message in the gateway source must be on that list, or they drop it.
#[test]
fn every_gateway_log_message_is_on_the_collector_list() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let list = message_list();
    let mut count = 0;
    for entry in std::fs::read_dir(root.join("src")).unwrap_or_else(|_| unreachable!()) {
        let path = entry.unwrap_or_else(|_| unreachable!()).path();
        let source = std::fs::read_to_string(&path).unwrap_or_else(|_| unreachable!());
        // Test modules may log freely; they never run in a deployment.
        let source = source.split("#[cfg(test)]").next().unwrap_or_default();
        for message in messages(source) {
            count += 1;
            if message == "{record}" {
                continue;
            }
            assert!(
                !message.contains('{'),
                "{}: a log message must be fixed text: {message}",
                path.display()
            );
            assert!(
                is_listed(&list, &message),
                "{}: add \"{message}\" to the chart's gateway message list",
                path.display()
            );
        }
    }
    assert!(count >= 10, "the message scan found only {count} messages");
}

/// The node log agent and the collector keep an audit record only in this
/// exact shape (the chart's audit pattern, [`AUDIT_RECORD`]).
#[test]
fn the_audit_record_has_the_shape_the_collector_keeps() {
    use confidential_gateway::{AuditEvent, AuditSink};
    let (captured, _guard) = capture();
    let sink = TracingAuditSink::new(log_privacy::KeyPseudonyms::from_secret(&SECRET));
    sink.record(AuditEvent {
        request_id: "c0ffee00-cafe-4000-8000-deadbeef0002".to_owned(),
        route: "/v1/chat/completions",
        status: 400,
        key_id: Some(KEY_RECORD.to_owned()),
    });
    sink.record(AuditEvent {
        request_id: "c0ffee00-cafe-4000-8000-deadbeef0003".to_owned(),
        route: "/v1/models",
        status: 200,
        key_id: None,
    });
    let pseudonym = log_privacy::KeyPseudonyms::from_secret(&SECRET).pseudonym(KEY_RECORD);
    let logs = captured.text();
    assert_reviewed(&logs);
    let messages: Vec<String> = logs
        .lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line).unwrap_or_default();
            assert_eq!(value["level"], "INFO", "{line}");
            assert!(value["timestamp"].is_string(), "{line}");
            value["message"].as_str().unwrap_or_default().to_owned()
        })
        .collect();
    assert_eq!(messages.len(), 2, "{logs}");
    assert_eq!(
        messages[0],
        format!(
            r#"{{"event":"gateway_request_completed","key_ref":"{pseudonym}","request_id":"c0ffee00-cafe-4000-8000-deadbeef0002","route":"/v1/chat/completions","status":400}}"#
        ),
        "{logs}"
    );
    assert_eq!(
        messages[1],
        r#"{"event":"gateway_request_completed","key_ref":null,"request_id":"c0ffee00-cafe-4000-8000-deadbeef0003","route":"/v1/models","status":200}"#,
        "{logs}"
    );
}
