//! The public confidential inference gateway.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::{Value, json};
use tower_http::{
    cors::{AllowHeaders, Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};
use uuid::Uuid;

pub mod admin_auth;
pub mod admin_client;
pub mod api_keys;
mod inference_api;
pub mod key_limits;
pub mod key_registry;
pub mod log_privacy;
mod messages;
pub mod metrics;
mod model_response;
pub mod protection;
pub mod request_body;
mod response_metrics;
pub mod routing_key;
pub mod settings;
pub mod usage;

use inference_api::Api;
use metrics::GatewayMetrics;
use protection::{ProtectionConfig, ProtectionState};
use response_metrics::ResponseMetrics;

pub trait ApiKeyVerifier: Send + Sync + 'static {
    fn verify_bearer(&self, bearer: &str) -> Option<String>;

    /// Return the stable record ID only when the supplied key is revoked.
    fn verify_revoked_bearer(&self, _bearer: &str) -> Option<String> {
        None
    }

    /// Return whether this verifier can authenticate a request right now.
    ///
    /// The key store is not ready before its first snapshot: it holds no
    /// key material yet, so the gateway refuses every request rather than
    /// reject every key as invalid, and `/ready` fails.
    fn is_ready(&self) -> bool {
        true
    }

    /// Admit or refuse one request of an authenticated key before it goes
    /// upstream (`crate::key_limits`). The default has no limits.
    ///
    /// # Errors
    ///
    /// Returns the limit that refused the request.
    fn admit(&self, _key_id: &str) -> Result<(), key_limits::LimitRejection> {
        Ok(())
    }

    /// Count the tokens of one finished request against the key's budget.
    fn record_tokens(&self, _key_id: &str, _tokens: u64) {}
}

pub trait AuditSink: Send + Sync + 'static {
    fn record(&self, event: AuditEvent);
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub request_id: String,
    pub route: &'static str,
    pub status: u16,
    pub key_id: Option<String>,
}

/// The audit sink of the running gateway: one log record per request.
///
/// The record holds only the fields below. Each value is a fixed route, a
/// status code, a gateway-made UUID, or a key pseudonym. The raw key record
/// ID never goes into a log record (`crate::log_privacy::KeyPseudonyms`).
pub struct TracingAuditSink {
    pseudonyms: log_privacy::KeyPseudonyms,
}

impl TracingAuditSink {
    #[must_use]
    pub fn new(pseudonyms: log_privacy::KeyPseudonyms) -> Self {
        Self { pseudonyms }
    }
}

impl AuditSink for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        // The collector clears log attributes. Put only the reviewed audit
        // fields in the body so the safe correlation metadata reaches it.
        let record = json!({
            "event": "gateway_request_completed",
            "request_id": event.request_id,
            "route": event.route,
            "status": event.status,
            "key_ref": event.key_id.as_deref().map(|key_id| self.pseudonyms.pseudonym(key_id)),
        });
        tracing::info!("{record}");
    }
}

#[derive(Clone)]
pub struct GatewayConfig {
    pub catalog_model_ids: Vec<String>,
    pub inference_model_ids: Vec<String>,
    pub upstream_base_url: String,
    pub maximum_body_bytes: usize,
    pub upstream_timeout: Duration,
    pub protection: ProtectionConfig,
}

#[derive(Clone)]
struct AppState {
    config: GatewayConfig,
    router_label: String,
    http: reqwest::Client,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    protection: Arc<ProtectionState>,
    usage: Option<Arc<usage::Recorder>>,
    routing_keys: Option<Arc<routing_key::RoutingKeys>>,
}

/// The largest `maximum_body_bytes` a deployment can configure: 64 MiB.
///
/// A 1M-token (1,048,576-token) text request needs about 12 MiB of JSON in a
/// realistic worst case, and the recommended limit for a 1M-token context is
/// 32 MiB. The ceiling leaves room for image input. A request can use about
/// four times its body size in gateway memory, so size the memory before you
/// raise the limit. See `docs/request-body-limit.md`.
pub const MAXIMUM_BODY_BYTES_CEILING: usize = 64 * 1024 * 1024;

pub fn router(
    config: GatewayConfig,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    http: reqwest::Client,
) -> Router {
    router_with_usage(config, keys, audit, metrics, http, None)
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_usage(
    config: GatewayConfig,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    http: reqwest::Client,
    usage: Option<Arc<usage::Recorder>>,
) -> Router {
    let protection = Arc::new(ProtectionState::new(config.protection.clone()));
    let router_label = url::Url::parse(&config.upstream_base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "fixed-router".into());
    let routing_keys = routing_key::RoutingKeys::generate()
        .inspect_err(|error| {
            tracing::error!(%error, "no routing key secret: the router routes requests at random");
        })
        .ok()
        .map(Arc::new);
    let state = Arc::new(AppState {
        config,
        router_label,
        http,
        keys,
        audit,
        metrics,
        protection: protection.clone(),
        usage,
        routing_keys,
    });
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/completions", post(completions))
        .route("/v1/responses", post(responses))
        .route("/v1/messages", post(messages))
        // The handler enforces the configured limit with the API error body.
        // This layer only bounds the largest limit the settings accept.
        .layer(RequestBodyLimitLayer::new(MAXIMUM_BODY_BYTES_CEILING))
        .layer(middleware::from_fn_with_state(
            protection,
            protection::enforce_public_limits,
        ))
        .layer(middleware::from_fn(messages_errors))
        .layer(middleware::from_fn(request_id))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([http::Method::GET, http::Method::POST])
                .expose_headers([http::HeaderName::from_static("x-ci-request-id")])
                .allow_headers(AllowHeaders::list([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    header::HeaderName::from_static("x-api-key"),
                    header::HeaderName::from_static("anthropic-version"),
                    header::HeaderName::from_static("anthropic-beta"),
                    header::HeaderName::from_static("anthropic-dangerous-direct-browser-access"),
                    routing_key::HEADER.clone(),
                ])),
        )
        .with_state(state)
}

async fn request_id(mut request: Request, next: Next) -> Response<Body> {
    let response_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_request_id(value))
        .map_or_else(|| Uuid::new_v4().to_string(), ToOwned::to_owned);
    // Caller IDs can contain customer text. Preserve the response contract,
    // but mint a separate ID for audit records and internal worker requests.
    let request_id = Uuid::new_v4().to_string();
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert("x-request-id", value);
    }
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&response_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-ci-request-id", value);
    }
    response
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

async fn health() -> impl IntoResponse {
    Json(json!({"status":"ok"}))
}

async fn ready(State(state): State<Arc<AppState>>) -> Response<Body> {
    if !state.keys.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"key_registry_not_ready"})),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({"status":"ready"}))).into_response()
}

async fn models(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response<Body> {
    let models: Vec<_> = state
        .config
        .catalog_model_ids
        .iter()
        .map(|id| json!({"id":id,"object":"model","owned_by":"confidential.ai"}))
        .collect();
    state.audit.record(AuditEvent {
        request_id: request_id_from(&headers),
        route: "/v1/models",
        status: 200,
        key_id: None,
    });
    (StatusCode::OK, Json(json!({"object":"list","data":models}))).into_response()
}

async fn chat_completions(State(state): State<Arc<AppState>>, request: Request) -> Response<Body> {
    proxy_inference(state, request, Api::ChatCompletions).await
}

async fn completions(State(state): State<Arc<AppState>>, request: Request) -> Response<Body> {
    proxy_inference(state, request, Api::Completions).await
}

/// The `OpenAI` Responses API. The `SGLang` worker serves it natively and the
/// router forwards it, so the gateway proxies it like the completion routes. The
/// gateway keeps no response state, so it accepts only stateless requests
/// (`inference_api::Api::prepare`).
async fn responses(State(state): State<Arc<AppState>>, request: Request) -> Response<Body> {
    proxy_inference(state, request, Api::Responses).await
}

async fn messages(State(state): State<Arc<AppState>>, mut request: Request) -> Response<Body> {
    // An explicit Authorization header takes precedence, even if invalid.
    if !request.headers().contains_key(header::AUTHORIZATION)
        && let Some(key) = request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
        && let Ok(value) = HeaderValue::from_str(&format!("Bearer {key}"))
    {
        request.headers_mut().insert(header::AUTHORIZATION, value);
    }
    messages::complete_json(proxy_inference(state, request, Api::Messages).await).await
}

/// Also render errors raised before the handler, such as address limits.
async fn messages_errors(request: Request, next: Next) -> Response<Body> {
    let messages =
        request.method() == http::Method::POST && request.uri().path() == Api::Messages.route();
    let response = next.run(request).await;
    if messages && !response.status().is_success() {
        messages::error_response(response)
    } else {
        response
    }
}

#[allow(clippy::too_many_lines)]
async fn proxy_inference(state: Arc<AppState>, request: Request, api: Api) -> Response<Body> {
    let route = api.route();
    let config = &state.config;
    let request_id = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if !state.keys.is_ready() {
        state.metrics.record_rejection("key_registry_not_ready");
        return client_error(StatusCode::SERVICE_UNAVAILABLE, "key_registry_not_ready");
    }
    let key_id = match authenticate(&state, request.headers()) {
        Authentication::Active(key_id) => key_id,
        Authentication::Revoked(key_id) => return revoked_key(&state, &key_id),
        Authentication::Invalid => return unauthorized(&state),
    };
    if let Err(rejection) = state.keys.admit(&key_id) {
        return limit_rejected(&state, &key_id, rejection);
    }
    let client_routing_key = request.headers().get(&routing_key::HEADER).cloned();
    let started = Instant::now();
    let router_request = state.metrics.router_request(&state.router_label);
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());
    if declared.is_some_and(|length| length > config.maximum_body_bytes) {
        return client_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
    }
    // The body's share of the memory budget, held until the router answers
    // (`crate::request_body`).
    let body_memory = &state.protection.body_memory;
    let mut body_reservation = match body_memory
        .reserve(
            request_body::read_cost(declared.unwrap_or(config.maximum_body_bytes)),
            config.protection.queue_timeout,
        )
        .await
    {
        Ok(reservation) => reservation,
        Err(error) => return body_memory_refused(&state, &error),
    };
    let body = match tokio::time::timeout(
        config.protection.body_timeout,
        request_body::read(request.into_body(), declared, config.maximum_body_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(request_body::ReadError::TooLarge)) => {
            return client_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
        }
        Ok(Err(request_body::ReadError::Failed)) => {
            return client_error(StatusCode::BAD_REQUEST, "request_body_failed");
        }
        Err(_) => return client_error(StatusCode::REQUEST_TIMEOUT, "request_body_timeout"),
    };
    if let Err(error) = body_reservation.resize(
        request_body::parse_cost(body.len(), request_body::shape(&body)),
        body_memory,
    ) {
        return body_memory_refused(&state, &error);
    }
    let mut payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return client_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    let Some(model) = payload
        .get("model")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return client_error(StatusCode::BAD_REQUEST, "model_required");
    };
    if !config
        .inference_model_ids
        .iter()
        .any(|candidate| candidate == &model)
    {
        state
            .metrics
            .record_key_rejection("model_not_authorized", &key_id);
        return client_error(StatusCode::UNAUTHORIZED, "model_not_authorized");
    }
    let model = model.as_str();
    let wire = api.wire();
    let body_changed = match api.prepare(&mut payload) {
        Ok(changed) => changed,
        Err(error) => {
            state.metrics.record_key_rejection(error.code(), &key_id);
            return error.response();
        }
    };
    let routing_key = state.routing_keys.as_ref().and_then(|keys| {
        keys.derive(
            &key_id,
            api.upstream_route(),
            client_routing_key.as_ref(),
            &payload,
        )
    });
    let mut usage_request = match &state.usage {
        Some(recorder) => {
            let Some(guard) = recorder.reserve(&key_id, model) else {
                state
                    .metrics
                    .record_key_rejection("usage_capacity", &key_id);
                return protection::overload("usage_capacity");
            };
            Some(guard.charge_to(state.keys.clone()))
        }
        None => None,
    };
    let internal_stream_usage = api.stream_usage(&payload, usage_request.is_some());
    let hide_final_usage = api.hide_usage(&payload, internal_stream_usage);
    let body = if internal_stream_usage || body_changed {
        if internal_stream_usage {
            if !payload.get("stream_options").is_some_and(Value::is_object) {
                payload["stream_options"] = json!({});
            }
            payload["stream_options"]["include_usage"] = json!(true);
        }
        // Drop the read body before the new one exists: the parsed value
        // holds the text.
        let capacity = body.len().saturating_add(256);
        drop(body);
        let mut written = Vec::with_capacity(capacity);
        match serde_json::to_writer(&mut written, &payload) {
            Ok(()) => axum::body::Bytes::from(written),
            Err(_) => return client_error(StatusCode::BAD_REQUEST, "invalid_json"),
        }
    } else {
        body
    };
    // Only the body to send stays: the parsed value goes before the queue.
    drop(payload);
    // A shrink cannot fail. A body that grew in the rewrite keeps the parse
    // share, which is larger than it.
    let _ = body_reservation.resize(body.len(), body_memory);
    let queue_started = Instant::now();
    state.metrics.enter_queue();
    let permits = state.protection.inference_permits(&key_id).await;
    state
        .metrics
        .leave_queue(queue_started.elapsed().as_secs_f64());
    let Ok(permits) = permits else {
        if let Some(usage) = &mut usage_request {
            usage.finish(usage::Outcome::Failed);
        }
        state
            .metrics
            .record_key_rejection("inference_capacity", &key_id);
        return protection::overload("inference_capacity");
    };
    let active_request = state.metrics.active_request();
    let mut upstream = state
        .http
        .post(format!(
            "{}{}",
            config.upstream_base_url,
            api.upstream_route()
        ))
        .timeout(config.upstream_timeout)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-request-id", &request_id);
    if let Some(value) = routing_key {
        upstream = upstream.header(routing_key::HEADER.clone(), value);
    }
    let upstream = upstream.body(body).send().await;
    // The router has the whole body once it answers.
    drop(body_reservation);
    let Ok(upstream) = upstream else {
        if let Some(usage) = &mut usage_request {
            usage.finish(usage::Outcome::Failed);
        }
        state.metrics.set_upstream_reachable(false);
        state.metrics.record_request(model, &key_id, 503);
        state
            .metrics
            .observe_request_duration(model, 503, started.elapsed().as_secs_f64());
        state.audit.record(AuditEvent {
            request_id,
            route,
            status: 503,
            key_id: Some(key_id),
        });
        return inference_unavailable();
    };
    state.metrics.set_upstream_reachable(true);
    let status = upstream.status();
    if status == StatusCode::SERVICE_UNAVAILABLE {
        if let Some(usage) = &mut usage_request {
            usage.finish(usage::Outcome::Failed);
        }
        state.metrics.set_upstream_reachable(false);
        state.metrics.record_request(model, &key_id, 503);
        state
            .metrics
            .observe_request_duration(model, 503, started.elapsed().as_secs_f64());
        state.audit.record(AuditEvent {
            request_id,
            route,
            status: 503,
            key_id: Some(key_id),
        });
        return inference_unavailable();
    }
    if !status.is_success() {
        // An error body of the inference server can quote the request, for
        // example a validation error with the offending input. The gateway
        // never reads, logs, or forwards it: the caller gets the status and a
        // fixed error body.
        if let Some(usage) = &mut usage_request {
            usage.finish(usage::Outcome::Failed);
        }
        let retry_after = safe_retry_after(upstream.headers());
        drop(upstream);
        state
            .metrics
            .record_request(model, &key_id, status.as_u16());
        state.metrics.observe_request_duration(
            model,
            status.as_u16(),
            started.elapsed().as_secs_f64(),
        );
        state.audit.record(AuditEvent {
            request_id,
            route,
            status: status.as_u16(),
            key_id: Some(key_id),
        });
        let mut response = upstream_error(status);
        if let Some(value) = retry_after {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        return response;
    }
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let is_event_stream = content_type
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let rewrite_model = status.is_success()
        && (is_event_stream
            || content_type
                .as_ref()
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("application/json")));
    let retry_after = safe_retry_after(upstream.headers());
    let first_token_timeout = config.protection.first_token_timeout;
    let idle_timeout = config.protection.stream_idle_timeout;
    let metrics = Arc::clone(&state.metrics);
    let metric_model = model.to_owned();
    let metric_key_id = key_id.clone();
    let stream = async_stream::stream! {
        let mut usage_request = usage_request;
        let _permits = permits;
        let _active_request = active_request;
        let _router_request = router_request;
        let mut upstream_stream = upstream.bytes_stream();
        let mut response_metrics = ResponseMetrics::new(wire);
        let mut observe = |value: &Value, observation| {
            response_metrics.observe(value, observation, &metrics, &metric_model, &metric_key_id, started);
        };
        let expected_model = usage_request.as_ref().map(|usage| usage.served_model().to_owned());
        let mut model_response = model_response::ModelResponse::new(metric_model.clone(), is_event_stream).hide_final_usage(hide_final_usage).expected_model(expected_model).wire(wire).with_output(api.output(is_event_stream));
        // The first chunk of a stream comes after the queue and the prefill
        // of the whole prompt, so it has its own, longer timeout.
        let mut wait = first_token_timeout;
        loop {
            match tokio::time::timeout(wait, upstream_stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    wait = idle_timeout;
                    if rewrite_model {
                        match model_response.push_observed(&chunk, &mut observe) {
                            Ok(output) => {
                                if let Some(usage) = &mut usage_request { usage.observation = model_response.observation(); if model_response.stream_done() { usage.finish(model_response.done_outcome()); } }
                                if !output.is_empty() { yield Ok::<_, std::io::Error>(axum::body::Bytes::from(output)); }
                            },
                            Err(error) => { if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); } yield model_response.failure(error).map(axum::body::Bytes::from); break; }
                        }
                    } else {
                        yield Ok::<_, std::io::Error>(chunk);
                    }
                },
                Ok(Some(Err(_))) => {
                    if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); }
                    yield model_response.failure(std::io::Error::other("upstream response failed")).map(axum::body::Bytes::from);
                    break;
                }
                Ok(None) => {
                    if rewrite_model {
                        match model_response.finish_observed(&mut observe) {
                            Ok(output) => {
                                if let Some(usage) = &mut usage_request {
                                    usage.observation = model_response.observation();
                                    usage.finish(if !is_event_stream || model_response.stream_done() { model_response.done_outcome() } else { usage::Outcome::Interrupted });
                                }
                                if !output.is_empty() { yield Ok(axum::body::Bytes::from(output)); }
                            },
                            Err(error) => { if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); } yield model_response.failure(error).map(axum::body::Bytes::from); },
                        }
                    } else if let Some(usage) = &mut usage_request {
                        usage.finish(if status.is_success() { usage::Outcome::Completed } else { usage::Outcome::Failed });
                    }
                    break;
                },
                Err(_) => {
                    if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); }
                    yield model_response.failure(std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream stream timed out")).map(axum::body::Bytes::from);
                    break;
                }
            }
        }
        response_metrics.finish(&metrics, &metric_model, &metric_key_id);
    };
    let mut response = Response::builder()
        .status(status)
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::empty()));
    if let Some(value) = content_type {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    if let Some(value) = retry_after {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    state
        .metrics
        .record_request(model, &key_id, status.as_u16());
    state
        .metrics
        .observe_request_duration(model, status.as_u16(), started.elapsed().as_secs_f64());
    state.audit.record(AuditEvent {
        request_id,
        route,
        status: status.as_u16(),
        key_id: Some(key_id),
    });
    response
}

fn body_memory_refused(state: &AppState, error: &request_body::ReserveError) -> Response<Body> {
    match error {
        request_body::ReserveError::TooLarge => {
            client_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large")
        }
        request_body::ReserveError::Busy => {
            state.metrics.record_rejection("body_memory_capacity");
            protection::overload("body_memory_capacity")
        }
    }
}

enum Authentication {
    Active(String),
    Revoked(String),
    Invalid,
}

fn authenticate(state: &AppState, headers: &HeaderMap) -> Authentication {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return Authentication::Invalid;
    };
    let Some(bearer) = value.strip_prefix("Bearer ") else {
        return Authentication::Invalid;
    };
    if bearer.is_empty() || bearer.len() > 256 {
        return Authentication::Invalid;
    }
    if let Some(key_id) = state.keys.verify_bearer(bearer) {
        Authentication::Active(key_id)
    } else if let Some(key_id) = state.keys.verify_revoked_bearer(bearer) {
        Authentication::Revoked(key_id)
    } else {
        Authentication::Invalid
    }
}

fn unauthorized(state: &AppState) -> Response<Body> {
    state.metrics.record_rejection("invalid_api_key");
    client_error(StatusCode::UNAUTHORIZED, "invalid_api_key")
}

fn revoked_key(state: &AppState, key_id: &str) -> Response<Body> {
    state
        .metrics
        .record_key_rejection("revoked_api_key", key_id);
    client_error(StatusCode::UNAUTHORIZED, "invalid_api_key")
}

/// A per-key limit refused the request. The body names only the limit
/// kind: no key ID, no limit value and no spend.
fn limit_rejected(
    state: &AppState,
    key_id: &str,
    rejection: key_limits::LimitRejection,
) -> Response<Body> {
    let (code, message, retry_after_seconds) = match rejection {
        key_limits::LimitRejection::RateLimited {
            retry_after_seconds,
        } => (
            "rate_limit_exceeded",
            "The API key sent too many requests. Wait, then try again.",
            retry_after_seconds,
        ),
        key_limits::LimitRejection::TokenBudgetExhausted {
            retry_after_seconds,
        } => (
            "insufficient_quota",
            "The API key used its token budget for this period.",
            retry_after_seconds,
        ),
    };
    state.metrics.record_key_rejection(code, key_id);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({"error":{"code":code,"message":message}})),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(inference_api::ErrorCode(code));
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_seconds));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn client_error(status: StatusCode, code: &'static str) -> Response<Body> {
    let code = inference_api::ErrorCode(code);
    let mut response = (
        status,
        Json(json!({"error":{"code":code.0,"message":status.canonical_reason().unwrap_or("Request failed.")}})),
    ).into_response();
    response.extensions_mut().insert(code);
    response
}

/// The fixed error body for a non-success status of the inference server.
/// The code tells the caller the class of the failure; the upstream text is
/// dropped.
fn upstream_error(status: StatusCode) -> Response<Body> {
    let code = match status.as_u16() {
        400 | 422 => "invalid_request",
        404 => "not_found",
        408 => "request_timeout",
        413 => "request_too_large",
        429 => "rate_limited",
        400..=499 => "request_rejected",
        _ => "inference_error",
    };
    let kind = if status.is_client_error() {
        "invalid_request_error"
    } else {
        "server_error"
    };
    inference_api::tag_error((
        status,
        Json(json!({"error":{
            "code": code,
            "type": kind,
            "param": null,
            "message": "The inference server did not accept the request. The gateway does not return its error text.",
        }})),
    )
        .into_response(), code)
}

fn inference_unavailable() -> Response<Body> {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":{
            "code":"inference_unavailable",
            "message":"Inference is temporarily unavailable."
        }})),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(inference_api::ErrorCode("inference_unavailable"));
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

fn safe_retry_after(headers: &HeaderMap) -> Option<HeaderValue> {
    let seconds = headers
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .parse::<u16>()
        .ok()?;
    if !(1..=3_600).contains(&seconds) {
        return None;
    }
    HeaderValue::from_str(&seconds.to_string()).ok()
}

fn request_id_from(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_request_id(value))
        .map_or_else(|| Uuid::new_v4().to_string(), ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MetricsSource;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    struct Keys;
    impl ApiKeyVerifier for Keys {
        fn verify_bearer(&self, value: &str) -> Option<String> {
            (value == "accepted").then(|| "key_record_1".to_owned())
        }

        fn verify_revoked_bearer(&self, value: &str) -> Option<String> {
            (value == "revoked").then(|| "key_record_revoked".to_owned())
        }
    }

    struct Audit;
    impl AuditSink for Audit {
        fn record(&self, _: AuditEvent) {}
    }

    /// A key store before its first snapshot: it holds no key material, so
    /// the gateway must refuse every request.
    struct NotReadyKeys;
    impl ApiKeyVerifier for NotReadyKeys {
        fn verify_bearer(&self, _value: &str) -> Option<String> {
            None
        }

        fn is_ready(&self) -> bool {
            false
        }
    }

    fn app() -> Router {
        app_with_keys(Arc::new(Keys))
    }

    fn app_with_keys(keys: Arc<dyn ApiKeyVerifier>) -> Router {
        router(
            GatewayConfig {
                catalog_model_ids: vec!["deepseek".to_owned()],
                inference_model_ids: vec!["deepseek".to_owned()],
                upstream_base_url: "http://127.0.0.1:1".to_owned(),
                maximum_body_bytes: 1_024,
                upstream_timeout: Duration::from_secs(1),
                protection: ProtectionConfig::default(),
            },
            keys,
            Arc::new(Audit),
            Arc::new(GatewayMetrics::new("test")),
            reqwest::Client::new(),
        )
    }

    fn authorization() -> (&'static str, &'static str) {
        ("authorization", "Bearer accepted")
    }

    #[tokio::test]
    async fn model_catalog_never_requires_an_api_key() {
        for authorization in [None, Some("Bearer invalid"), Some("Bearer revoked")] {
            let mut request = Request::builder().uri("/v1/models");
            if let Some(value) = authorization {
                request = request.header(header::AUTHORIZATION, value);
            }
            let response = app()
                .oneshot(
                    request
                        .body(Body::empty())
                        .unwrap_or_else(|_| unreachable!()),
                )
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 1_024)
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap_or_default()["data"],
                json!([
                    {"id":"deepseek","object":"model","owned_by":"confidential.ai"}
                ])
            );
        }
    }

    #[tokio::test]
    async fn unsupported_models_are_not_authorized() {
        for model in ["minimax-m3", "unknown"] {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/chat/completions")
                        .header(authorization().0, authorization().1)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(format!(r#"{{"model":"{model}"}}"#)))
                        .unwrap_or_else(|_| unreachable!()),
                )
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let body = to_bytes(response.into_body(), 1_024)
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap_or_default()["error"]["code"],
                "model_not_authorized"
            );
        }
    }

    #[tokio::test]
    async fn a_store_without_keys_keeps_the_catalog_and_rejects_inference() {
        let app = app_with_keys(Arc::new(NotReadyKeys));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/models")
                    .header(authorization().0, authorization().1)
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap_or_default()["data"],
            json!([
                {"id":"deepseek","object":"model","owned_by":"confidential.ai"}
            ])
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(authorization().0, authorization().1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"model":"deepseek"}"#))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readiness_waits_for_the_keys() {
        let response = app_with_keys(Arc::new(NotReadyKeys))
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readiness_does_not_depend_on_inference() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap_or_default(),
            json!({"status":"ready"})
        );
    }

    #[tokio::test]
    async fn unreachable_inference_returns_a_structured_503() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(authorization().0, authorization().1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"model":"deepseek"}"#))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "30");
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap_or_default()["error"]["code"],
            "inference_unavailable"
        );
    }

    #[tokio::test]
    async fn a_cold_start_registry_verifier_answers_service_unavailable() {
        let app = app_with_keys(Arc::new(NotReadyKeys));
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header(authorization().0, authorization().1)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"model":"deepseek"}"#))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 1_024)
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(
            serde_json::from_slice::<Value>(&body).unwrap_or_default()["error"]["code"],
            "key_registry_not_ready"
        );
    }

    #[tokio::test]
    async fn browsers_may_send_a_routing_key() {
        let response = app()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/chat/completions")
                    .header(header::ORIGIN, "https://client.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "x-smg-routing-key")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        let allowed = response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS]
            .to_str()
            .unwrap_or_default();
        assert!(allowed.contains("x-smg-routing-key"), "{allowed}");
    }

    #[test]
    fn retry_after_accepts_only_bounded_integer_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        assert_eq!(
            safe_retry_after(&headers),
            Some(HeaderValue::from_static("60"))
        );
        headers.insert(
            header::RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2030 07:28:00 GMT"),
        );
        assert_eq!(safe_retry_after(&headers), None);
        headers.insert(header::RETRY_AFTER, HeaderValue::from_static("65535"));
        assert_eq!(safe_retry_after(&headers), None);
    }

    #[test]
    fn records_only_safe_openai_usage_from_json() {
        let metrics = GatewayMetrics::new("production");
        let mut response = model_response::ModelResponse::new("deepseek".into(), false);
        let mut facts = ResponseMetrics::new(model_response::Wire::Completions);
        response.push_observed(br#"{"choices":[{"message":{"content":"private"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3}}}"#, &mut |_, _| {}).unwrap_or_else(|_| unreachable!());
        response
            .finish_observed(&mut |value, observation| {
                facts.observe(
                    value,
                    observation,
                    &metrics,
                    "deepseek",
                    "key_safe_1",
                    Instant::now(),
                );
            })
            .unwrap_or_else(|_| unreachable!());
        facts.finish(&metrics, "deepseek", "key_safe_1");
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("gen_ai_client_token_usage"));
        assert!(rendered.contains("key_id=\"key_safe_1\""));
        assert!(rendered.contains("type=\"input\""));
        assert!(rendered.contains("type=\"output\""));
        assert!(rendered.contains("gen_ai_usage_cache_read_input_tokens"));
        assert!(rendered.contains("reason=\"stop\""));
        assert!(!rendered.contains("private"));
    }

    #[test]
    fn records_stream_timing_and_usage_without_content() {
        let metrics = GatewayMetrics::new("production");
        let mut stream = ResponseMetrics::new(model_response::Wire::Completions);
        let mut response = model_response::ModelResponse::new("deepseek".into(), true);
        let started = Instant::now();
        response
            .push_observed(
                b"data: {\"choices\":[{\"delta\":{\"content\":\"SENSITIVE_OUTPUT_123\"}}]}\n\n",
                &mut |value, observation| {
                    stream.observe(
                        value,
                        observation,
                        &metrics,
                        "deepseek",
                        "key_safe_2",
                        started,
                    );
                },
            )
            .unwrap_or_else(|_| unreachable!());
        response.push_observed(b"data: {\"choices\":[{\"delta\":{\"content\":\"SENSITIVE_OUTPUT_456\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":1}}}\n\n", &mut |value, observation| stream.observe(value, observation, &metrics, "deepseek", "key_safe_2", started)).unwrap_or_else(|_| unreachable!());
        stream.finish(&metrics, "deepseek", "key_safe_2");
        let rendered = metrics.render_prometheus();
        assert!(rendered.contains("gen_ai_server_time_to_first_token_count"));
        assert!(rendered.contains("gateway_time_to_first_token_seconds_count"));
        assert!(rendered.contains("cache_status=\"cached\""));
        assert!(rendered.contains("gen_ai_server_time_per_output_token_count"));
        assert!(rendered.contains("gateway_tokens_per_second_count"));
        assert!(rendered.contains("gen_ai_client_token_usage"));
        assert!(!rendered.contains("SENSITIVE_OUTPUT_123"));
        assert!(!rendered.contains("SENSITIVE_OUTPUT_456"));
    }
}
