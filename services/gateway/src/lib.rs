//! The public confidential inference gateway.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Query, Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode, header},
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post},
};
use base64::Engine as _;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::{
    cors::{AllowHeaders, Any, CorsLayer},
    limit::RequestBodyLimitLayer,
};
use uuid::Uuid;

pub mod admin_auth;
pub mod api_keys;
pub mod attestation;
pub mod key_registry;
pub mod metrics;
pub mod protection;

use metrics::GatewayMetrics;
use protection::{ProtectionConfig, ProtectionState};

pub trait ApiKeyVerifier: Send + Sync + 'static {
    fn verify_bearer(&self, bearer: &str) -> Option<String>;

    /// Return the stable record ID only when the supplied key is revoked.
    fn verify_revoked_bearer(&self, _bearer: &str) -> Option<String> {
        None
    }

    /// Return the stable record ID and the source that matched it.
    ///
    /// The gateway state overrides this to report `"local"` or `"registry"`.
    /// The default reports every match as `"local"`, so a verifier with one
    /// key source needs no change.
    fn verify_bearer_with_source(&self, bearer: &str) -> Option<(String, &'static str)> {
        self.verify_bearer(bearer).map(|key_id| (key_id, "local"))
    }

    /// Return whether this verifier can authenticate a request right now.
    ///
    /// A verifier that reads only a registry cache is not ready before its
    /// first successful snapshot fetch: it holds no key material yet, so it
    /// must refuse every request rather than reject every key as invalid.
    fn is_ready(&self) -> bool {
        true
    }
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

pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: AuditEvent) {
        tracing::info!(
            request_id = %event.request_id,
            route = event.route,
            status = event.status,
            key_id = ?event.key_id,
            "gateway request completed"
        );
    }
}

#[derive(Clone)]
pub struct GatewayAvailability {
    available: Arc<std::sync::atomic::AtomicBool>,
}

impl GatewayAvailability {
    #[must_use]
    pub fn new(available: bool) -> Self {
        Self {
            available: Arc::new(std::sync::atomic::AtomicBool::new(available)),
        }
    }

    #[must_use]
    pub fn is_available(&self) -> bool {
        self.available.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn set_available(&self, available: bool) {
        self.available
            .store(available, std::sync::atomic::Ordering::Release);
    }
}

impl Default for GatewayAvailability {
    fn default() -> Self {
        Self::new(true)
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
    http: reqwest::Client,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    availability: GatewayAvailability,
    attestation_provider: Arc<dyn AttestationProvider>,
    nonces: Arc<Mutex<NonceStore>>,
    protection: Arc<ProtectionState>,
}

#[async_trait::async_trait]
pub trait AttestationProvider: Send + Sync + 'static {
    /// Create evidence for one caller nonce.
    ///
    /// # Errors
    ///
    /// Returns an error when evidence is unavailable or invalid.
    async fn response(&self, nonce: &[u8; 32]) -> Result<Value, AttestationError>;
}

#[derive(Debug)]
pub enum AttestationError {
    Unavailable,
    Invalid,
}

pub struct UnavailableAttestation;

#[async_trait::async_trait]
impl AttestationProvider for UnavailableAttestation {
    async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
        Err(AttestationError::Unavailable)
    }
}

const NONCE_CAPACITY: usize = 4_096;
const NONCE_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Default)]
struct NonceStore {
    used: std::collections::BTreeMap<[u8; 32], Instant>,
}

impl NonceStore {
    fn reserve(&mut self, nonce: [u8; 32]) -> bool {
        let now = Instant::now();
        self.used.retain(|_, timestamp| {
            now.checked_duration_since(*timestamp)
                .is_none_or(|age| age < NONCE_TTL)
        });
        if self.used.contains_key(&nonce) || self.used.len() >= NONCE_CAPACITY {
            return false;
        }
        self.used.insert(nonce, now);
        true
    }

    fn release_failed(&mut self, nonce: &[u8; 32]) {
        self.used.remove(nonce);
    }
}

#[allow(clippy::too_many_arguments)]
pub fn router(
    config: GatewayConfig,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    availability: GatewayAvailability,
    attestation_provider: Arc<dyn AttestationProvider>,
    http: reqwest::Client,
) -> Router {
    let maximum_body_bytes = config.maximum_body_bytes;
    let protection = Arc::new(ProtectionState::new(config.protection.clone()));
    let state = Arc::new(AppState {
        config,
        http,
        keys,
        audit,
        metrics,
        availability,
        attestation_provider,
        nonces: Arc::new(Mutex::new(NonceStore::default())),
        protection: protection.clone(),
    });
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/completions", post(completions))
        .route("/attestation", get(attestation_response))
        .route("/v1/attestation", get(attestation_response))
        .layer(RequestBodyLimitLayer::new(maximum_body_bytes))
        .layer(middleware::from_fn_with_state(
            protection,
            protection::enforce_public_limits,
        ))
        .layer(middleware::from_fn(request_id))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([http::Method::GET, http::Method::POST])
                .allow_headers(AllowHeaders::list([
                    header::AUTHORIZATION,
                    header::CONTENT_TYPE,
                    header::ACCEPT,
                    header::HeaderName::from_static("x-attestation-nonce"),
                ])),
        )
        .with_state(state)
}

async fn request_id(mut request: Request, next: Next) -> Response<Body> {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_request_id(value))
        .map_or_else(|| Uuid::new_v4().to_string(), ToOwned::to_owned);
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
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
    if !state.availability.is_available() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"outage_only"})),
        )
            .into_response();
    }
    match state
        .http
        .get(format!("{}/health", state.config.upstream_base_url))
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            state.metrics.set_upstream_reachable(true);
            (StatusCode::OK, Json(json!({"status":"ready"}))).into_response()
        }
        _ => {
            state.metrics.set_upstream_reachable(false);
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status":"not_ready"})),
            )
                .into_response()
        }
    }
}

async fn models(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response<Body> {
    if !state.availability.is_available() {
        return (StatusCode::OK, Json(json!({"object":"list","data":[]}))).into_response();
    }
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
    proxy_inference(state, request, "/v1/chat/completions").await
}

async fn completions(State(state): State<Arc<AppState>>, request: Request) -> Response<Body> {
    proxy_inference(state, request, "/v1/completions").await
}

#[allow(clippy::too_many_lines)]
async fn proxy_inference(
    state: Arc<AppState>,
    request: Request,
    route: &'static str,
) -> Response<Body> {
    let request_id = request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if !state.availability.is_available() {
        state.metrics.record_rejection("gateway_state_unavailable");
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error":{"code":"gateway_state_unavailable","message":"Inference is temporarily unavailable."}})),
        )
            .into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        return response;
    }
    if !state.keys.is_ready() {
        state.metrics.record_rejection("key_registry_not_ready");
        return client_error(StatusCode::SERVICE_UNAVAILABLE, "key_registry_not_ready");
    }
    let key_id = match authenticate(&state, request.headers()) {
        Authentication::Active(key_id) => key_id,
        Authentication::Revoked(key_id) => return revoked_key(&state, &key_id),
        Authentication::Invalid => return unauthorized(&state),
    };
    let started = Instant::now();
    let body = match tokio::time::timeout(
        state.config.protection.body_timeout,
        axum::body::to_bytes(request.into_body(), state.config.maximum_body_bytes),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return client_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
        }
        Err(_) => return client_error(StatusCode::REQUEST_TIMEOUT, "request_body_timeout"),
    };
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return client_error(StatusCode::BAD_REQUEST, "invalid_json"),
    };
    let Some(model) = payload.get("model").and_then(Value::as_str) else {
        return client_error(StatusCode::BAD_REQUEST, "model_required");
    };
    if !state
        .config
        .inference_model_ids
        .iter()
        .any(|candidate| candidate == model)
    {
        state.metrics.record_rejection("model_not_authorized");
        return client_error(StatusCode::UNAUTHORIZED, "model_not_authorized");
    }
    let queue_started = Instant::now();
    state.metrics.enter_queue();
    let permits = state.protection.inference_permits(&key_id).await;
    state
        .metrics
        .leave_queue(queue_started.elapsed().as_secs_f64());
    let Ok(permits) = permits else {
        state.metrics.record_rejection("inference_capacity");
        return protection::overload("inference_capacity");
    };
    let active_request = state.metrics.active_request();
    let upstream = state
        .http
        .post(format!("{}{route}", state.config.upstream_base_url))
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-request-id", &request_id)
        .body(body)
        .send()
        .await;
    let Ok(upstream) = upstream else {
        state.metrics.set_upstream_reachable(false);
        state.metrics.record_request(model, &key_id, 502);
        state
            .metrics
            .observe_request_duration(model, 502, started.elapsed().as_secs_f64());
        state.audit.record(AuditEvent {
            request_id,
            route,
            status: 502,
            key_id: Some(key_id),
        });
        return client_error(StatusCode::BAD_GATEWAY, "upstream_unavailable");
    };
    state.metrics.set_upstream_reachable(true);
    let status = upstream.status();
    let content_type = upstream.headers().get(header::CONTENT_TYPE).cloned();
    let is_event_stream = content_type
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/event-stream"));
    let retry_after = safe_retry_after(upstream.headers());
    let idle_timeout = state.config.protection.stream_idle_timeout;
    let metrics = Arc::clone(&state.metrics);
    let metric_model = model.to_owned();
    let metric_key_id = key_id.clone();
    let stream = async_stream::stream! {
        let _permits = permits;
        let _active_request = active_request;
        let mut upstream_stream = upstream.bytes_stream();
        let mut stream_metrics = StreamMetrics::default();
        let mut json_metrics = Vec::new();
        let mut json_metrics_overflow = false;
        loop {
            match tokio::time::timeout(idle_timeout, upstream_stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    if is_event_stream {
                        stream_metrics.observe(
                            &chunk,
                            &metrics,
                            &metric_model,
                            &metric_key_id,
                            started,
                        );
                    } else if !json_metrics_overflow {
                        if json_metrics.len().saturating_add(chunk.len()) <= 1_048_576 {
                            json_metrics.extend_from_slice(&chunk);
                        } else {
                            json_metrics.clear();
                            json_metrics_overflow = true;
                        }
                    }
                    yield Ok::<_, std::io::Error>(chunk)
                },
                Ok(Some(Err(_))) => {
                    yield Err(std::io::Error::other("upstream response failed"));
                    break;
                }
                Ok(None) => break,
                Err(_) => {
                    yield Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream stream timed out"));
                    break;
                }
            }
        }
        if !is_event_stream && !json_metrics_overflow {
            record_safe_openai_metrics(&metrics, &metric_model, &metric_key_id, &json_metrics);
        } else if is_event_stream {
            stream_metrics.finish(&metrics, &metric_model, &metric_key_id);
        }
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

/// Read only bounded numeric usage fields from an OpenAI-compatible response.
/// Prompt text, output text, tool arguments, and headers are never retained.
fn record_safe_openai_metrics(metrics: &GatewayMetrics, model: &str, key_id: &str, body: &[u8]) {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return;
    };
    record_safe_openai_value(metrics, model, key_id, &value);
}

fn record_safe_openai_value(metrics: &GatewayMetrics, model: &str, key_id: &str, value: &Value) {
    if let Some(usage) = value.get("usage") {
        if let Some(tokens) = usage.get("prompt_tokens").and_then(Value::as_u64) {
            metrics.add_token_usage(model, key_id, "input", tokens);
        }
        if let Some(tokens) = usage.get("completion_tokens").and_then(Value::as_u64) {
            metrics.add_token_usage(model, key_id, "output", tokens);
        }
        let cached_tokens = cached_input_tokens(usage);
        if let Some(tokens) = cached_tokens {
            metrics.add_cache_read_input_tokens(model, key_id, tokens);
        }
    }
    record_finish_reasons(metrics, model, value);
}

fn cached_input_tokens(usage: &Value) -> Option<u64> {
    if let Some(details) = usage.get("prompt_tokens_details") {
        if details.is_null() {
            // SGLang emits this explicit value when no prompt token came from
            // cache. An absent field remains unclassified.
            return Some(0);
        }
        return details.get("cached_tokens").and_then(Value::as_u64);
    }
    usage.get("cache_read_input_tokens").and_then(Value::as_u64)
}

fn record_finish_reasons(metrics: &GatewayMetrics, model: &str, value: &Value) {
    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return;
    };
    for choice in choices {
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            metrics.record_finish_reason(model, reason);
        }
    }
}

#[derive(Default)]
struct StreamMetrics {
    pending: String,
    first_output_at: Option<Instant>,
    last_output_at: Option<Instant>,
    output_tokens: Option<u64>,
    cached_input_tokens: Option<u64>,
    ttft_seconds: Option<f64>,
}

impl StreamMetrics {
    fn observe(
        &mut self,
        chunk: &[u8],
        metrics: &GatewayMetrics,
        model: &str,
        key_id: &str,
        request_started: Instant,
    ) {
        let Ok(text) = std::str::from_utf8(chunk) else {
            return;
        };
        self.pending.push_str(text);
        while let Some(newline) = self.pending.find('\n') {
            let line = self.pending[..newline].trim_end_matches('\r').to_owned();
            self.pending.drain(..=newline);
            let Some(data) = line.strip_prefix("data: ") else {
                continue;
            };
            if data == "[DONE]" {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(data) else {
                continue;
            };
            record_safe_openai_value(metrics, model, key_id, &value);
            if let Some(usage) = value.get("usage")
                && let Some(tokens) = cached_input_tokens(usage)
            {
                self.cached_input_tokens = Some(tokens);
            }
            if let Some(tokens) = value
                .get("usage")
                .and_then(|usage| usage.get("completion_tokens"))
                .and_then(Value::as_u64)
            {
                self.output_tokens = Some(tokens);
            }
            if has_output_delta(&value) {
                let now = Instant::now();
                match self.last_output_at.replace(now) {
                    None => {
                        self.first_output_at = Some(now);
                        let ttft_seconds = request_started.elapsed().as_secs_f64();
                        self.ttft_seconds = Some(ttft_seconds);
                        metrics.observe_time_to_first_token(model, key_id, ttft_seconds);
                    }
                    Some(previous) => metrics.observe_time_per_output_token(
                        model,
                        key_id,
                        now.duration_since(previous).as_secs_f64(),
                    ),
                }
            }
        }
    }

    fn finish(&self, metrics: &GatewayMetrics, model: &str, key_id: &str) {
        if let (Some(ttft_seconds), Some(cached_input_tokens)) =
            (self.ttft_seconds, self.cached_input_tokens)
        {
            metrics.observe_cache_classified_time_to_first_token(
                model,
                key_id,
                cached_input_tokens > 0,
                ttft_seconds,
            );
        }
        let (Some(tokens), Some(first), Some(last)) = (
            self.output_tokens,
            self.first_output_at,
            self.last_output_at,
        ) else {
            return;
        };
        let seconds = last.duration_since(first).as_secs_f64();
        if tokens > 1 && seconds > 0.0 {
            let generated = u32::try_from(tokens - 1).map_or(f64::from(u32::MAX), f64::from);
            metrics.observe_tokens_per_second(model, key_id, generated / seconds);
        }
    }
}

fn has_output_delta(value: &Value) -> bool {
    value
        .get("choices")
        .and_then(Value::as_array)
        .is_some_and(|choices| {
            choices.iter().any(|choice| {
                choice
                    .get("delta")
                    .and_then(Value::as_object)
                    .is_some_and(|delta| {
                        ["content", "reasoning_content"].iter().any(|field| {
                            delta
                                .get(*field)
                                .and_then(Value::as_str)
                                .is_some_and(|text| !text.is_empty())
                        })
                    })
            })
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestationQuery {
    nonce: Option<String>,
}

async fn attestation_response(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AttestationQuery>,
    headers: HeaderMap,
) -> Response<Body> {
    let Ok(_permit) = state.protection.attestation_permit() else {
        state.metrics.record_rejection("attestation_capacity");
        return protection::overload("attestation_capacity");
    };
    let header_values = headers.get_all("x-attestation-nonce");
    if header_values.iter().count() > 1 {
        return client_error(StatusCode::BAD_REQUEST, "ambiguous_nonce");
    }
    let header_nonce = header_values
        .iter()
        .next()
        .and_then(|value| value.to_str().ok());
    if query.nonce.is_some() && header_nonce.is_some() {
        return client_error(StatusCode::BAD_REQUEST, "ambiguous_nonce");
    }
    let encoded = query.nonce.as_deref().or(header_nonce);
    let Some(encoded) = encoded else {
        return client_error(StatusCode::BAD_REQUEST, "nonce_required");
    };
    if encoded.len() != 43 {
        return client_error(StatusCode::BAD_REQUEST, "invalid_nonce");
    }
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded) else {
        return client_error(StatusCode::BAD_REQUEST, "invalid_nonce");
    };
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return client_error(StatusCode::BAD_REQUEST, "invalid_nonce");
    }
    let Ok(nonce) = <[u8; 32]>::try_from(bytes) else {
        return client_error(StatusCode::BAD_REQUEST, "invalid_nonce");
    };
    let reserved = state
        .nonces
        .lock()
        .map(|mut store| store.reserve(nonce))
        .unwrap_or(false);
    if !reserved {
        return client_error(StatusCode::CONFLICT, "nonce_rejected");
    }
    match state.attestation_provider.response(&nonce).await {
        Ok(response) => {
            let mut response = (StatusCode::OK, Json(response)).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, max-age=0"),
            );
            response
        }
        Err(AttestationError::Invalid) => {
            release_failed_nonce(&state, &nonce);
            client_error(StatusCode::BAD_GATEWAY, "attestation_invalid")
        }
        Err(AttestationError::Unavailable) => {
            release_failed_nonce(&state, &nonce);
            client_error(StatusCode::SERVICE_UNAVAILABLE, "attestation_unavailable")
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
    if let Some((key_id, source)) = state.keys.verify_bearer_with_source(bearer) {
        state.metrics.record_api_key_accepted(source);
        Authentication::Active(key_id)
    } else if let Some(key_id) = state.keys.verify_revoked_bearer(bearer) {
        Authentication::Revoked(key_id)
    } else {
        Authentication::Invalid
    }
}

fn release_failed_nonce(state: &AppState, nonce: &[u8; 32]) {
    if let Ok(mut store) = state.nonces.lock() {
        store.release_failed(nonce);
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

fn client_error(status: StatusCode, code: &'static str) -> Response<Body> {
    (
        status,
        Json(json!({"error":{"code":code,"message":status.canonical_reason().unwrap_or("Request failed.")}})),
    )
        .into_response()
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

    /// A `registry`-mode verifier before its first successful snapshot
    /// fetch: it holds no key material, so it must refuse every request.
    struct NotReadyKeys;
    impl ApiKeyVerifier for NotReadyKeys {
        fn verify_bearer(&self, _value: &str) -> Option<String> {
            None
        }

        fn is_ready(&self) -> bool {
            false
        }
    }

    fn app(availability: GatewayAvailability) -> Router {
        app_with_attestation(availability, Arc::new(UnavailableAttestation))
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
            GatewayAvailability::default(),
            Arc::new(UnavailableAttestation),
            reqwest::Client::new(),
        )
    }

    fn app_with_attestation(
        availability: GatewayAvailability,
        provider: Arc<dyn AttestationProvider>,
    ) -> Router {
        router(
            GatewayConfig {
                catalog_model_ids: vec!["deepseek".to_owned(), "minimax-m3".to_owned()],
                inference_model_ids: vec!["deepseek".to_owned()],
                upstream_base_url: "http://127.0.0.1:1".to_owned(),
                maximum_body_bytes: 1_024,
                upstream_timeout: Duration::from_secs(1),
                protection: ProtectionConfig::default(),
            },
            Arc::new(Keys),
            Arc::new(Audit),
            Arc::new(GatewayMetrics::new("test")),
            availability,
            provider,
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
            let response = app(GatewayAvailability::default())
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
                    {"id":"deepseek","object":"model","owned_by":"confidential.ai"},
                    {"id":"minimax-m3","object":"model","owned_by":"confidential.ai"}
                ])
            );
        }
    }

    #[tokio::test]
    async fn unsupported_models_are_not_authorized() {
        for model in ["minimax-m3", "unknown"] {
            let response = app(GatewayAvailability::default())
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
    async fn unavailable_state_hides_models_and_rejects_inference() {
        let app = app(GatewayAvailability::new(false));
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
            json!([])
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
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "30");
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
    async fn a_failed_attestation_does_not_burn_the_nonce() {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([4_u8; 32]);
        let app = app(GatewayAvailability::default());
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/attestation?nonce={nonce}"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        let replay = app
            .oneshot(
                Request::builder()
                    .uri(format!("/attestation?nonce={nonce}"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(replay.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    struct Evidence;

    #[async_trait::async_trait]
    impl AttestationProvider for Evidence {
        async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
            Ok(json!({"evidence":"test"}))
        }
    }

    #[tokio::test]
    async fn a_successful_attestation_nonce_is_single_use() {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([5_u8; 32]);
        let app = app_with_attestation(GatewayAvailability::default(), Arc::new(Evidence));
        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/attestation?nonce={nonce}"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(first.status(), StatusCode::OK);
        let replay = app
            .oneshot(
                Request::builder()
                    .uri(format!("/attestation?nonce={nonce}"))
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(replay.status(), StatusCode::CONFLICT);
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
        record_safe_openai_metrics(
            &metrics,
            "deepseek",
            "key_safe_1",
            br#"{"choices":[{"message":{"content":"private"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"prompt_tokens_details":{"cached_tokens":3}}}"#,
        );
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
    fn classifies_sglang_null_cache_details_as_cold() {
        assert_eq!(
            cached_input_tokens(&json!({"prompt_tokens_details": null})),
            Some(0)
        );
        assert_eq!(
            cached_input_tokens(&json!({"prompt_tokens_details": {"cached_tokens": 64}})),
            Some(64)
        );
        assert_eq!(cached_input_tokens(&json!({"prompt_tokens": 64})), None);
    }

    #[test]
    fn records_stream_timing_and_usage_without_content() {
        let metrics = GatewayMetrics::new("production");
        let mut stream = StreamMetrics::default();
        let started = Instant::now();
        stream.observe(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"SENSITIVE_OUTPUT_123\"}}]}\n\n",
            &metrics,
            "deepseek",
            "key_safe_2",
            started,
        );
        stream.observe(
            b"data: {\"choices\":[{\"delta\":{\"content\":\"SENSITIVE_OUTPUT_456\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":1}}}\n\n",
            &metrics,
            "deepseek",
            "key_safe_2",
            started,
        );
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
