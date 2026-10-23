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
pub mod admin_client;
pub mod api_keys;
pub mod attestation;
pub mod attestation_metadata;
mod capacity;
pub mod key_registry;
pub mod metrics;
mod model_response;
pub mod protection;
pub mod release_settings;
pub mod runtime_config;
pub mod runtime_settings;
pub mod usage;

use metrics::GatewayMetrics;
use protection::{ProtectionConfig, ProtectionState};

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
    runtime: Option<Arc<runtime_config::MountedConfig<runtime_settings::GatewaySettings>>>,
    router_namespace: Option<String>,
    fixed_router_label: String,
    router_origin: Option<(String, u16)>,
    http: reqwest::Client,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    attestation_provider: Arc<dyn AttestationProvider>,
    nonces: Arc<Mutex<NonceStore>>,
    protection: Arc<ProtectionState>,
    usage: Option<Arc<usage::Recorder>>,
}

#[async_trait::async_trait]
pub trait AttestationProvider: Send + Sync + 'static {
    /// Legacy evidence needs a caller nonce; policy metadata does not.
    fn requires_nonce(&self) -> bool {
        true
    }
    /// Create evidence for one caller nonce.
    ///
    /// # Errors
    ///
    /// Returns an error when evidence is unavailable or invalid.
    async fn response(&self, nonce: &[u8; 32]) -> Result<Value, AttestationError>;
}

#[derive(Clone, Debug)]
pub enum AttestationError {
    /// The producer could not reach or read an upstream evidence source. The
    /// string names the step that failed and carries no evidence bytes.
    Unavailable(String),
    /// The producer read the evidence and rejected it. The string names the
    /// check that refused it and carries no evidence bytes.
    Invalid(String),
    /// The c8s node speaks a different attestation protocol than this build.
    /// The string names the cause and comes from the c8s error body.
    ProtocolMismatch(String),
}

pub struct UnavailableAttestation;

#[async_trait::async_trait]
impl AttestationProvider for UnavailableAttestation {
    async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
        Err(AttestationError::Unavailable(
            "this gateway build has no attestation producer configured".to_owned(),
        ))
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
    attestation_provider: Arc<dyn AttestationProvider>,
    http: reqwest::Client,
) -> Router {
    router_with_runtime(
        config,
        keys,
        audit,
        metrics,
        attestation_provider,
        http,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_runtime(
    config: GatewayConfig,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    attestation_provider: Arc<dyn AttestationProvider>,
    http: reqwest::Client,
    runtime: Option<Arc<runtime_config::MountedConfig<runtime_settings::GatewaySettings>>>,
    router_namespace: Option<String>,
) -> Router {
    router_with_runtime_and_usage(
        config,
        keys,
        audit,
        metrics,
        attestation_provider,
        http,
        runtime,
        router_namespace,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn router_with_runtime_and_usage(
    config: GatewayConfig,
    keys: Arc<dyn ApiKeyVerifier>,
    audit: Arc<dyn AuditSink>,
    metrics: Arc<GatewayMetrics>,
    attestation_provider: Arc<dyn AttestationProvider>,
    http: reqwest::Client,
    runtime: Option<Arc<runtime_config::MountedConfig<runtime_settings::GatewaySettings>>>,
    router_namespace: Option<String>,
    usage: Option<Arc<usage::Recorder>>,
) -> Router {
    let maximum_body_bytes = if runtime.is_some() {
        8 * 1024 * 1024
    } else {
        config.maximum_body_bytes
    };
    let protection =
        Arc::new(ProtectionState::new(config.protection.clone()).with_runtime(runtime.clone()));
    let fixed_router_label = url::Url::parse(&config.upstream_base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .unwrap_or_else(|| "fixed-router".into());
    let router_origin = url::Url::parse(&config.upstream_base_url)
        .ok()
        .and_then(|url| {
            url.port_or_known_default()
                .map(|port| (url.scheme().to_owned(), port))
        });
    let state = Arc::new(AppState {
        config,
        runtime,
        router_namespace,
        fixed_router_label,
        router_origin,
        http,
        keys,
        audit,
        metrics,
        attestation_provider,
        nonces: Arc::new(Mutex::new(NonceStore::default())),
        protection: protection.clone(),
        usage,
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
    if !state.keys.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"key_registry_not_ready"})),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({"status":"ready"}))).into_response()
}

struct RequestConfig<'a> {
    base: &'a GatewayConfig,
    runtime: Option<Arc<runtime_settings::GatewaySettings>>,
    router_namespace: Option<&'a str>,
    fixed_router_label: &'a str,
    router_origin: Option<(&'a str, u16)>,
}

impl RequestConfig<'_> {
    fn router_label(&self) -> String {
        match (
            self.runtime
                .as_ref()
                .and_then(|settings| settings.router_service.as_ref()),
            self.router_namespace,
        ) {
            (Some(service), Some(namespace)) => format!("{service}.{namespace}.svc.cluster.local"),
            _ => self.fixed_router_label.to_owned(),
        }
    }
    fn upstream_url(&self, route: &str) -> Option<String> {
        if let Some(service) = self
            .runtime
            .as_ref()
            .and_then(|settings| settings.router_service.as_ref())
        {
            let namespace = self.router_namespace?;
            let (scheme, port) = self.router_origin?;
            // The namespace and port are startup trust inputs. Runtime data
            // can select only a router Service in this namespace.
            return Some(format!(
                "{scheme}://{service}.{namespace}.svc.cluster.local:{port}{route}"
            ));
        }
        Some(format!("{}{route}", self.base.upstream_base_url))
    }
    fn catalog_model_ids(&self) -> &[String] {
        self.runtime
            .as_ref()
            .map_or(&self.base.catalog_model_ids, |value| {
                &value.catalog_model_ids
            })
    }
    fn inference_model_ids(&self) -> &[String] {
        self.runtime
            .as_ref()
            .map_or(&self.base.inference_model_ids, |value| {
                &value.inference_model_ids
            })
    }
    fn maximum_body_bytes(&self) -> usize {
        self.runtime
            .as_ref()
            .map_or(self.base.maximum_body_bytes, |value| {
                value.maximum_body_bytes
            })
    }
    fn upstream_timeout(&self) -> Duration {
        self.runtime
            .as_ref()
            .map_or(self.base.upstream_timeout, |value| {
                Duration::from_secs(value.upstream_timeout_seconds)
            })
    }
    fn body_timeout(&self) -> Duration {
        self.runtime
            .as_ref()
            .map_or(self.base.protection.body_timeout, |value| {
                Duration::from_secs(value.body_timeout_seconds)
            })
    }
    fn stream_idle_timeout(&self) -> Duration {
        self.runtime
            .as_ref()
            .map_or(self.base.protection.stream_idle_timeout, |value| {
                Duration::from_secs(value.stream_idle_timeout_seconds)
            })
    }
}

fn request_config(state: &AppState) -> RequestConfig<'_> {
    RequestConfig {
        base: &state.config,
        runtime: state.runtime.as_ref().map(|source| source.snapshot()),
        router_namespace: state.router_namespace.as_deref(),
        fixed_router_label: &state.fixed_router_label,
        router_origin: state
            .router_origin
            .as_ref()
            .map(|(scheme, port)| (scheme.as_str(), *port)),
    }
}

async fn models(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response<Body> {
    let config = request_config(&state);
    let models: Vec<_> = config
        .catalog_model_ids()
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
    // Capture once. An accepted update cannot change an active request or stream.
    let config = request_config(&state);
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
    let started = Instant::now();
    let router_request = state.metrics.router_request(config.router_label());
    let body = match tokio::time::timeout(
        config.body_timeout(),
        axum::body::to_bytes(request.into_body(), config.maximum_body_bytes()),
    )
    .await
    {
        Ok(Ok(body)) => body,
        Ok(Err(_)) => {
            return client_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large");
        }
        Err(_) => return client_error(StatusCode::REQUEST_TIMEOUT, "request_body_timeout"),
    };
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
        .inference_model_ids()
        .iter()
        .any(|candidate| candidate == &model)
    {
        state.metrics.record_rejection("model_not_authorized");
        return client_error(StatusCode::UNAUTHORIZED, "model_not_authorized");
    }
    let model = model.as_str();
    let mut usage_request = match &state.usage {
        Some(recorder) => match recorder.reserve(&key_id, model) {
            Some(guard) => Some(guard),
            None => return protection::overload("usage_capacity"),
        },
        None => None,
    };
    let internal_stream_usage =
        usage_request.is_some() && payload.get("stream").and_then(Value::as_bool) == Some(true);
    let hide_final_usage = internal_stream_usage
        && payload
            .get("stream_options")
            .and_then(|v| v.get("include_usage"))
            .and_then(Value::as_bool)
            != Some(true);
    let body = if internal_stream_usage {
        if !payload.get("stream_options").is_some_and(Value::is_object) {
            payload["stream_options"] = json!({});
        }
        payload["stream_options"]["include_usage"] = json!(true);
        match serde_json::to_vec(&payload) {
            Ok(body) => axum::body::Bytes::from(body),
            Err(_) => return client_error(StatusCode::BAD_REQUEST, "invalid_json"),
        }
    } else {
        body
    };
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
        state.metrics.record_rejection("inference_capacity");
        return protection::overload("inference_capacity");
    };
    let active_request = state.metrics.active_request();
    let Some(upstream_url) = config.upstream_url(route) else {
        return inference_unavailable();
    };
    let upstream = state
        .http
        .post(upstream_url)
        .timeout(config.upstream_timeout())
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-request-id", &request_id)
        .body(body)
        .send()
        .await;
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
    let idle_timeout = config.stream_idle_timeout();
    let metrics = Arc::clone(&state.metrics);
    let metric_model = model.to_owned();
    let metric_key_id = key_id.clone();
    let stream = async_stream::stream! {
        let mut usage_request = usage_request;
        let _permits = permits;
        let _active_request = active_request;
        let _router_request = router_request;
        let runtime_snapshot = config.runtime;
        let mut upstream_stream = upstream.bytes_stream();
        let mut stream_metrics = StreamMetrics::default();
        let mut json_metrics = Vec::new();
        let mut json_metrics_overflow = false;
        let expected_model = usage_request.as_ref().map(|usage| usage.served_model().to_owned());
        let mut model_response = model_response::ModelResponse::new(metric_model.clone(), is_event_stream).hide_final_usage(hide_final_usage).expected_model(expected_model);
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
                    if rewrite_model {
                        match model_response.push(&chunk) {
                            Ok(output) => {
                                if let Some(usage) = &mut usage_request { usage.observation = model_response.observation(); if model_response.stream_done() { usage.finish(usage::Outcome::Completed); } }
                                if !output.is_empty() { yield Ok::<_, std::io::Error>(axum::body::Bytes::from(output)); }
                            },
                            Err(error) => { if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); } yield Err(error); break; }
                        }
                    } else {
                        yield Ok::<_, std::io::Error>(chunk);
                    }
                },
                Ok(Some(Err(_))) => {
                    if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); }
                    yield Err(std::io::Error::other("upstream response failed"));
                    break;
                }
                Ok(None) => {
                    if rewrite_model {
                        match model_response.finish() {
                            Ok(output) => {
                                if let Some(usage) = &mut usage_request {
                                    usage.observation = model_response.observation();
                                    usage.finish(if !is_event_stream || model_response.stream_done() { usage::Outcome::Completed } else { usage::Outcome::Interrupted });
                                }
                                if !output.is_empty() { yield Ok(axum::body::Bytes::from(output)); }
                            },
                            Err(error) => { if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); } yield Err(error); },
                        }
                    } else if let Some(usage) = &mut usage_request {
                        usage.finish(if status.is_success() { usage::Outcome::Completed } else { usage::Outcome::Failed });
                    }
                    break;
                },
                Err(_) => {
                    if let Some(usage) = &mut usage_request { usage.finish(usage::Outcome::Interrupted); }
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
        drop(runtime_snapshot);
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

async fn metadata_attestation_response(state: &AppState) -> Response<Body> {
    let started = Instant::now();
    let result = state.attestation_provider.response(&[0; 32]).await;
    let status = if result.is_ok() { 200 } else { 503 };
    state
        .metrics
        .record_attestation_response(status, started.elapsed().as_secs_f64());
    match result {
        Ok(document) => {
            let mut response = Json(document).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("no-store, max-age=0"),
            );
            response
        }
        // Same diagnosis channel as the nonce path below: the detail names
        // the failed step and never carries evidence or key material.
        Err(
            AttestationError::Unavailable(detail)
            | AttestationError::Invalid(detail)
            | AttestationError::ProtocolMismatch(detail),
        ) => {
            tracing::warn!(step = %detail, "attestation metadata is unavailable");
            let mut response = detailed_client_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "attestation_unavailable",
                &detail,
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
    }
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
    if !state.attestation_provider.requires_nonce() {
        return metadata_attestation_response(&state).await;
    }
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
        // Every 5xx this handler emits names the step that failed. The
        // gateway runs where kubelet logs and exec are disabled, so the
        // response body is the only diagnosis channel. The detail never
        // carries evidence bytes, key material, or a nonce.
        Err(AttestationError::Invalid(detail)) => {
            release_failed_nonce(&state, &nonce);
            detailed_client_error(StatusCode::BAD_GATEWAY, "attestation_invalid", &detail)
        }
        Err(AttestationError::Unavailable(detail)) => {
            release_failed_nonce(&state, &nonce);
            detailed_client_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "attestation_unavailable",
                &detail,
            )
        }
        // A protocol mismatch is version skew between this gateway and c8s.
        // It is not failed attestation, and it gets its own code and a detail
        // string so the cause is visible in the response itself.
        Err(AttestationError::ProtocolMismatch(detail)) => {
            release_failed_nonce(&state, &nonce);
            detailed_client_error(
                StatusCode::BAD_GATEWAY,
                "attestation_protocol_mismatch",
                &detail,
            )
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
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
    response
}

fn detailed_client_error(status: StatusCode, code: &'static str, detail: &str) -> Response<Body> {
    (
        status,
        Json(json!({"error":{
            "code": code,
            "message": status.canonical_reason().unwrap_or("Request failed."),
            "detail": detail,
        }})),
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
        app_with(Arc::new(Keys), Arc::new(UnavailableAttestation))
    }

    fn app_with_keys(keys: Arc<dyn ApiKeyVerifier>) -> Router {
        app_with(keys, Arc::new(UnavailableAttestation))
    }

    fn app_with(keys: Arc<dyn ApiKeyVerifier>, provider: Arc<dyn AttestationProvider>) -> Router {
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
            provider,
            reqwest::Client::new(),
        )
    }

    fn authorization() -> (&'static str, &'static str) {
        ("authorization", "Bearer accepted")
    }

    #[tokio::test]
    async fn metadata_attestation_needs_no_key_nonce_or_live_inference_upstream() {
        struct Metadata;
        #[async_trait::async_trait]
        impl AttestationProvider for Metadata {
            fn requires_nonce(&self) -> bool {
                false
            }
            async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
                Ok(json!({"schemaVersion": 3, "c8s": {"operatorKeys": []}}))
            }
        }
        // The configured inference address has no listener and no key is
        // loaded. Attestation must still work.
        for path in ["/attestation", "/v1/attestation"] {
            let response = app_with(Arc::new(NotReadyKeys), Arc::new(Metadata))
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap_or_else(|error| panic!("{error:?}")),
                )
                .await
                .unwrap_or_else(|error| panic!("{error:?}"));
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "no-store, max-age=0"
            );
            let body = to_bytes(response.into_body(), 1024)
                .await
                .unwrap_or_else(|error| panic!("{error:?}"));
            let document: Value =
                serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error:?}"));
            assert_eq!(document["schemaVersion"], 3);
            assert!(document.get("nonce").is_none());
            assert!(document.get("receipts").is_none());
        }
    }

    #[tokio::test]
    async fn metadata_attestation_failure_names_the_failed_step() {
        struct Failing;
        #[async_trait::async_trait]
        impl AttestationProvider for Failing {
            fn requires_nonce(&self) -> bool {
                false
            }
            async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
                Err(AttestationError::Unavailable("GET CDS metadata".to_owned()))
            }
        }
        let response = app_with_attestation(GatewayAvailability::default(), Arc::new(Failing))
            .oneshot(
                Request::builder()
                    .uri("/v1/attestation")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("{error:?}")),
            )
            .await
            .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::RETRY_AFTER], "1");
        let body = to_bytes(response.into_body(), 1024)
            .await
            .unwrap_or_else(|error| panic!("{error:?}"));
        let document: Value =
            serde_json::from_slice(&body).unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(document["error"]["code"], "attestation_unavailable");
        assert_eq!(document["error"]["detail"], "GET CDS metadata");
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
    async fn a_failed_attestation_does_not_burn_the_nonce() {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([4_u8; 32]);
        let app = app();
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
        let app = app_with(Arc::new(Keys), Arc::new(Evidence));
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
