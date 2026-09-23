//! The stateless maintenance response router.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ipnet::IpNet;
use serde_json::{Value, json};
use tokio::sync::Semaphore;

const MAX_HEADERS: usize = 64;
const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_URI_BYTES: usize = 2 * 1024;
const MAX_CONCURRENT_REQUESTS: usize = 128;
const MAX_CONCURRENT_REQUESTS_PER_ADDRESS: usize = 16;
const MAX_BODY_BYTES: usize = 64 * 1024;
const BODY_TIMEOUT: Duration = Duration::from_secs(5);
const ADDRESS_CAPACITY: usize = 4_096;
const REQUESTS_PER_ADDRESS_PER_SECOND: u32 = 30;
const DEEPSEEK_MODEL_ID: &str = "deepseek-ai/DeepSeek-V4-Flash-0731";

#[derive(Clone, Default)]
pub struct ProtectionConfig {
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

#[derive(Clone)]
struct ProtectionState {
    config: ProtectionConfig,
    requests: Arc<Semaphore>,
    addresses: Arc<Mutex<BTreeMap<IpAddr, (Instant, u32)>>>,
    address_slots: Arc<Mutex<BTreeMap<IpAddr, Arc<Semaphore>>>>,
}

fn json_response(status: StatusCode, body: Value) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn models() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "object": "list",
            "data": [
                {"id": DEEPSEEK_MODEL_ID, "object": "model", "owned_by": "confidential.ai"}
            ]
        }),
    )
}

async fn unavailable() -> Response {
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({
            "error": {
                "message": "Inference is temporarily unavailable.",
                "type": "service_unavailable",
                "param": null,
                "code": "inference_unavailable"
            }
        }),
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
    response
}

async fn health() -> Response {
    json_response(
        StatusCode::OK,
        json!({"status": "live", "mode": "maintenance", "inferenceAvailable": false}),
    )
}

async fn readiness() -> Response {
    json_response(
        StatusCode::OK,
        json!({"status": "ready", "mode": "maintenance", "inferenceAvailable": false}),
    )
}

async fn attestation() -> Response {
    json_response(
        StatusCode::OK,
        json!({
            "mode": "maintenance",
            "inferenceAvailable": false,
            "inferenceWorkloads": [],
            "attestationType": "outage-status",
            "statement": "This maintenance gateway runs no inference workload."
        }),
    )
}

async fn not_found() -> Response {
    json_response(
        StatusCode::NOT_FOUND,
        json!({
            "error": {
                "message": "Route not found.",
                "type": "invalid_request_error",
                "param": null,
                "code": "not_found"
            }
        }),
    )
}

async fn enforce_limits(
    State(state): State<Arc<ProtectionState>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(_permit) = state.requests.clone().try_acquire_owned() else {
        return limited("request_capacity");
    };
    let header_bytes = request
        .headers()
        .iter()
        .fold(0usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
        });
    if request.headers().len() > MAX_HEADERS || header_bytes > MAX_HEADER_BYTES {
        return json_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            json!({"error": {"code": "request_headers_too_large"}}),
        );
    }
    if request.uri().to_string().len() > MAX_URI_BYTES {
        return json_response(
            StatusCode::URI_TOO_LONG,
            json!({"error": {"code": "request_uri_too_long"}}),
        );
    }
    let Ok(client) = client_address(&request, &state.config) else {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error":{"code":"invalid_forwarding_headers"}}),
        );
    };
    if !accept_address(&state, client) {
        return limited("address_rate_limited");
    }
    let address_slots = {
        let Ok(mut slots) = state.address_slots.lock() else {
            return limited("request_capacity");
        };
        if !slots.contains_key(&client) && slots.len() >= ADDRESS_CAPACITY {
            return limited("address_capacity");
        }
        slots
            .entry(client)
            .or_insert_with(|| Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS_PER_ADDRESS)))
            .clone()
    };
    let Ok(_address_permit) = address_slots.try_acquire_owned() else {
        return limited("address_capacity");
    };
    let (parts, body) = request.into_parts();
    let Ok(Ok(_)) =
        tokio::time::timeout(BODY_TIMEOUT, axum::body::to_bytes(body, MAX_BODY_BYTES)).await
    else {
        return json_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            json!({"error":{"code":"request_body_too_large"}}),
        );
    };
    let request = Request::from_parts(parts, axum::body::Body::empty());
    next.run(request).await
}

fn client_address(request: &Request, config: &ProtectionConfig) -> Result<IpAddr, ()> {
    if request.headers().contains_key("forwarded") {
        return Err(());
    }
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|value| value.0.ip());
    let Some(forwarded) = request.headers().get("x-forwarded-for") else {
        return Ok(peer.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    };
    let peer = peer.ok_or(())?;
    if !config
        .trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(&peer))
    {
        return Err(());
    }
    let text = forwarded.to_str().map_err(|_| ())?;
    if text.contains(',') || text.trim() != text {
        return Err(());
    }
    let address: IpAddr = text.parse().map_err(|_| ())?;
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        let real_ip = real_ip.to_str().map_err(|_| ())?;
        if real_ip.trim() != real_ip
            || real_ip.contains(',')
            || real_ip.parse::<IpAddr>().map_err(|_| ())? != address
        {
            return Err(());
        }
    }
    Ok(address)
}

fn accept_address(state: &ProtectionState, client: IpAddr) -> bool {
    let now = Instant::now();
    let Ok(mut addresses) = state.addresses.lock() else {
        return false;
    };
    addresses.retain(|_, (started, _)| now.duration_since(*started) < Duration::from_secs(2));
    if !addresses.contains_key(&client) && addresses.len() >= ADDRESS_CAPACITY {
        return false;
    }
    let window = addresses.entry(client).or_insert((now, 0));
    if now.duration_since(window.0) >= Duration::from_secs(1) {
        *window = (now, 0);
    }
    if window.1 >= REQUESTS_PER_ADDRESS_PER_SECOND {
        return false;
    }
    window.1 += 1;
    true
}

fn limited(code: &'static str) -> Response {
    let mut response = json_response(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"error":{"code":code}}),
    );
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// Build the complete public maintenance router.
pub fn app() -> Router {
    app_with_config(ProtectionConfig::default())
}

/// Build the public maintenance router with its trusted proxy list.
pub fn app_with_config(config: ProtectionConfig) -> Router {
    let state = Arc::new(ProtectionState {
        config,
        requests: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
        addresses: Arc::new(Mutex::new(BTreeMap::new())),
        address_slots: Arc::new(Mutex::new(BTreeMap::new())),
    });
    Router::new()
        .route("/v1/models", get(models))
        .route("/v1/completions", post(unavailable))
        .route("/v1/chat/completions", post(unavailable))
        .route("/v1/responses", post(unavailable))
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/attestation", get(attestation))
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(state, enforce_limits))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    async fn response(method: &str, uri: &str) -> Response {
        app()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("test request failed: {error}")),
            )
            .await
            .unwrap_or_else(|error| match error {})
    }

    async fn json_body(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|error| panic!("test response failed: {error}"));
        serde_json::from_slice(&bytes).unwrap_or_else(|error| panic!("test JSON failed: {error}"))
    }

    #[tokio::test]
    async fn models_include_production_catalog() {
        let response = response("GET", "/v1/models").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await,
            json!({
                "object":"list",
                "data":[
                    {"id":DEEPSEEK_MODEL_ID,"object":"model","owned_by":"confidential.ai"}
                ]
            })
        );
    }

    #[tokio::test]
    async fn all_inference_routes_return_the_stable_429() {
        for route in ["/v1/completions", "/v1/chat/completions", "/v1/responses"] {
            let response = response("POST", route).await;
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                response.headers().get(header::RETRY_AFTER),
                Some(&HeaderValue::from_static("60"))
            );
            assert_eq!(
                json_body(response).await["error"]["code"],
                "inference_unavailable"
            );
        }
    }

    #[tokio::test]
    async fn status_routes_make_no_inference_claim() {
        for (route, status) in [("/health", "live"), ("/readiness", "ready")] {
            let body = json_body(response("GET", route).await).await;
            assert_eq!(body["status"], status);
            assert_eq!(body["inferenceAvailable"], false);
        }
        let body = json_body(response("GET", "/attestation").await).await;
        assert_eq!(body["attestationType"], "outage-status");
        assert_eq!(body["inferenceWorkloads"], json!([]));
    }

    #[tokio::test]
    async fn unknown_routes_return_safe_json() {
        let response = response("GET", "/unknown?token=test-only-not-a-secret").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(json_body(response).await["error"]["code"], "not_found");
    }

    #[tokio::test]
    async fn oversized_headers_and_uris_fail_before_routing() {
        let large_header = "a".repeat(MAX_HEADER_BYTES + 1);
        let header_response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-large", large_header)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("test request failed: {error}")),
            )
            .await
            .unwrap_or_else(|error| match error {});
        assert_eq!(
            header_response.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );

        let uri = format!("/{}", "a".repeat(MAX_URI_BYTES + 1));
        let uri_response = response("GET", &uri).await;
        assert_eq!(uri_response.status(), StatusCode::URI_TOO_LONG);
    }

    #[tokio::test]
    async fn spoofed_forwarding_headers_fail_closed() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-forwarded-for", "198.51.100.2")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|error| match error {});
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
