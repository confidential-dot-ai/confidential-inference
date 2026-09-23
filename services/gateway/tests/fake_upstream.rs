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
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayAvailability, GatewayConfig,
    UnavailableAttestation, metrics::GatewayMetrics, router,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
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

async fn spawn_upstream() -> (SocketAddr, oneshot::Sender<()>) {
    async fn completion(Json(value): Json<Value>) -> Json<Value> {
        Json(json!({
            "id": "response-1",
            "object": "chat.completion",
            "model": value["model"],
            "choices": [{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]
        }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(completion))
                .into_make_service(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, stop_tx)
}

async fn spawn_unavailable_upstream() -> (SocketAddr, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route(
                "/v1/chat/completions",
                post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            ),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, stop_tx)
}

async fn spawn_redirect_upstream(
    status: StatusCode,
    location: String,
) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route(
                "/v1/chat/completions",
                post(move || {
                    let location = location.clone();
                    async move { (status, [(header::LOCATION, location)]) }
                }),
            ),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, stop_tx)
}

async fn spawn_capture() -> (SocketAddr, Arc<AtomicUsize>, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let body_length = Arc::new(AtomicUsize::new(0));
    let observed_body_length = Arc::clone(&body_length);
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route(
                "/capture",
                post(move |body: Bytes| {
                    let observed_body_length = Arc::clone(&observed_body_length);
                    async move {
                        observed_body_length.store(body.len(), Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, body_length, stop_tx)
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| unreachable!())
}

fn app_with_client(address: SocketAddr, client: reqwest::Client) -> Router {
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
        Arc::new(GatewayMetrics::new("test")),
        GatewayAvailability::default(),
        Arc::new(UnavailableAttestation),
        client,
    )
}

fn app(address: SocketAddr) -> Router {
    app_with_client(address, no_redirect_client())
}

#[tokio::test]
async fn gateway_forwards_to_the_internal_router_without_the_caller_key() {
    let (address, stop) = spawn_upstream().await;
    let response = app(address)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"model":"deepseek","messages":[{"role":"user","content":"hello"}]})
                        .to_string(),
                ))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), 200);
    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_does_not_authorize_an_unknown_model_for_forwarding() {
    let (address, stop) = spawn_upstream().await;
    let response = app(address)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(json!({"model":"unknown"}).to_string()))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), 401);
    let body = axum::body::to_bytes(response.into_body(), 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default()["error"]["code"],
        "model_not_authorized"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_normalizes_an_unavailable_inference_router() {
    let (address, stop) = spawn_unavailable_upstream().await;
    let response = app(address)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(json!({"model":"deepseek"}).to_string()))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "30");
    let body = axum::body::to_bytes(response.into_body(), 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap_or_default()["error"]["code"],
        "inference_unavailable"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_does_not_forward_request_bodies_on_upstream_redirects() {
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        let (capture_address, capture_body_length, capture_stop) = spawn_capture().await;
        let location = format!("http://{capture_address}/capture");
        let (redirect_address, redirect_stop) = spawn_redirect_upstream(status, location).await;
        let response = app(redirect_address)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer accepted")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "model":"deepseek",
                            "messages":[{"role":"user","content":"secret prompt"}]
                        })
                        .to_string(),
                    ))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), status);
        assert!(
            capture_body_length.load(Ordering::SeqCst) == 0,
            "the redirect forwarded the request body"
        );
        let _ = redirect_stop.send(());
        let _ = capture_stop.send(());
    }
}
