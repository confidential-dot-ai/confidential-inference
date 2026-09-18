//! Privacy-safe Prometheus metrics for the private listener.
//!
//! This module deliberately accepts only fixed metadata and numeric values.
//! It has no API that can receive a prompt, completion, header, or plaintext
//! API key.  The public metric interface is `metrics-contract.md`.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{Arc, Mutex},
};

use axum::{Router, response::IntoResponse, routing::get};

const HISTOGRAM_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];
const TOKEN_BUCKETS: &[f64] = &[
    1.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1_024.0, 2_048.0, 4_096.0, 8_192.0,
    16_384.0, 32_768.0,
];
const TOKEN_RATE_BUCKETS: &[f64] = &[
    1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1_000.0,
];

/// Provides only the names and labels published in `metrics-contract.md`.
/// Values must not contain request content, headers, or plaintext keys.
pub trait MetricsSource: Send + Sync + 'static {
    fn render_prometheus(&self) -> String;
}

/// The complete in-process gateway metric registry.
///
/// `key_id` values are accepted only from [`crate::ApiKeyVerifier`], which
/// returns stable opaque control-plane record IDs. Callers must use rejection
/// metrics for unauthenticated requests instead of inventing a key label.
pub struct GatewayMetrics {
    environment: String,
    state: Mutex<MetricsState>,
}

#[derive(Default)]
struct MetricsState {
    requests: BTreeMap<RequestLabels, u64>,
    rejections: BTreeMap<RejectionLabels, u64>,
    upstream_reachable: bool,
    active_requests: u64,
    queue_depth: u64,
    queue_duration: Histogram,
    request_duration: BTreeMap<RequestDurationLabels, Histogram>,
    ttft: BTreeMap<ModelKeyLabels, Histogram>,
    cache_classified_ttft: BTreeMap<ModelKeyCacheLabels, Histogram>,
    output_token_time: BTreeMap<ModelKeyLabels, Histogram>,
    tokens_per_second: BTreeMap<ModelKeyLabels, Histogram>,
    token_usage: BTreeMap<TokenUsageLabels, u64>,
    input_tokens_per_request: BTreeMap<ModelKeyLabels, Histogram>,
    output_tokens_per_request: BTreeMap<ModelKeyLabels, Histogram>,
    cache_read_tokens: BTreeMap<ModelKeyLabels, u64>,
    finish_reasons: BTreeMap<ModelReasonLabels, u64>,
    key_registry_stale_seconds: f64,
    key_registry_pull_failures: BTreeMap<&'static str, u64>,
    key_registry_revision: i64,
    key_registry_pepper_mismatch_rows: u64,
    api_key_accepted: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequestLabels {
    model: String,
    key_id: String,
    status: u16,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RequestDurationLabels {
    model: String,
    status: u16,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RejectionLabels {
    reason: String,
    key_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelKeyLabels {
    model: String,
    key_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelKeyCacheLabels {
    model: String,
    key_id: String,
    cache_status: &'static str,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TokenUsageLabels {
    model: String,
    key_id: String,
    token_type: &'static str,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ModelReasonLabels {
    model: String,
    reason: &'static str,
}

#[derive(Clone)]
struct Histogram {
    bounds: &'static [f64],
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            bounds: HISTOGRAM_BUCKETS,
            buckets: vec![0; HISTOGRAM_BUCKETS.len()],
            count: 0,
            sum: 0.0,
        }
    }
}

impl Histogram {
    fn tokens() -> Self {
        Self {
            bounds: TOKEN_BUCKETS,
            buckets: vec![0; TOKEN_BUCKETS.len()],
            count: 0,
            sum: 0.0,
        }
    }

    fn token_rate() -> Self {
        Self {
            bounds: TOKEN_RATE_BUCKETS,
            buckets: vec![0; TOKEN_RATE_BUCKETS.len()],
            count: 0,
            sum: 0.0,
        }
    }

    fn observe(&mut self, seconds: f64) {
        if !seconds.is_finite() || seconds < 0.0 {
            return;
        }
        self.count = self.count.saturating_add(1);
        self.sum += seconds;
        for (index, bucket) in self.bounds.iter().enumerate() {
            if seconds <= *bucket {
                self.buckets[index] = self.buckets[index].saturating_add(1);
            }
        }
    }
}

impl GatewayMetrics {
    /// The process validates this as a DNS-label environment name.
    /// before it builds the registry.
    #[must_use]
    pub fn new(environment: impl Into<String>) -> Self {
        Self {
            environment: environment.into(),
            state: Mutex::new(MetricsState::default()),
        }
    }

    /// Every authenticated inference request is counted once, after a status
    /// is known. Authentication failures use [`Self::record_rejection`], so a
    /// fake `key_id` can never enter Prometheus.
    pub fn record_request(&self, model: &str, key_id: &str, status: u16) {
        let mut state = recover_lock(&self.state);
        *state
            .requests
            .entry(RequestLabels {
                model: model.to_owned(),
                key_id: key_id.to_owned(),
                status,
            })
            .or_default() += 1;
    }

    /// Record a pre-forwarding rejection with a fixed code, never caller data.
    pub fn record_rejection(&self, reason: &'static str) {
        let mut state = recover_lock(&self.state);
        *state
            .rejections
            .entry(RejectionLabels {
                reason: reason.to_owned(),
                key_id: String::new(),
            })
            .or_default() += 1;
    }

    /// Record a rejection for an already known opaque key record ID.
    pub fn record_key_rejection(&self, reason: &'static str, key_id: &str) {
        let mut state = recover_lock(&self.state);
        *state
            .rejections
            .entry(RejectionLabels {
                reason: reason.to_owned(),
                key_id: key_id.to_owned(),
            })
            .or_default() += 1;
    }

    /// Reflect the outcome of the most recent connection to the model node.
    pub fn set_upstream_reachable(&self, reachable: bool) {
        recover_lock(&self.state).upstream_reachable = reachable;
    }

    /// Mark one request as waiting for an inference execution slot.
    pub fn enter_queue(&self) {
        let mut state = recover_lock(&self.state);
        state.queue_depth = state.queue_depth.saturating_add(1);
    }

    /// Mark one request as no longer waiting and record its bounded wait time.
    pub fn leave_queue(&self, seconds: f64) {
        let mut state = recover_lock(&self.state);
        state.queue_depth = state.queue_depth.saturating_sub(1);
        state.queue_duration.observe(seconds);
    }

    /// Hold one active-request gauge slot until the returned guard is dropped.
    #[must_use]
    pub fn active_request(self: &Arc<Self>) -> ActiveRequestGuard {
        let mut state = recover_lock(&self.state);
        state.active_requests = state.active_requests.saturating_add(1);
        ActiveRequestGuard {
            metrics: Arc::clone(self),
        }
    }

    /// Observe caller-visible request time for an authenticated inference call.
    pub fn observe_request_duration(&self, model: &str, status: u16, seconds: f64) {
        let mut state = recover_lock(&self.state);
        state
            .request_duration
            .entry(RequestDurationLabels {
                model: model.to_owned(),
                status,
            })
            .or_default()
            .observe(seconds);
    }

    /// Observe first generated output delivery, not connection setup.
    pub fn observe_time_to_first_token(&self, model: &str, key_id: &str, seconds: f64) {
        observe_model_key(
            &self.state,
            &mut |state| &mut state.ttft,
            model,
            key_id,
            seconds,
        );
    }

    /// Record caller-visible TTFT after the upstream reports whether it reused
    /// any cached input tokens. The bounded label cannot contain caller data.
    pub fn observe_cache_classified_time_to_first_token(
        &self,
        model: &str,
        key_id: &str,
        cached: bool,
        seconds: f64,
    ) {
        let mut state = recover_lock(&self.state);
        state
            .cache_classified_ttft
            .entry(ModelKeyCacheLabels {
                model: model.to_owned(),
                key_id: key_id.to_owned(),
                cache_status: if cached { "cached" } else { "cold" },
            })
            .or_default()
            .observe(seconds);
    }

    /// Observe time between generated output deliveries.
    pub fn observe_time_per_output_token(&self, model: &str, key_id: &str, seconds: f64) {
        observe_model_key(
            &self.state,
            &mut |state| &mut state.output_token_time,
            model,
            key_id,
            seconds,
        );
    }

    /// Observe one completed streaming request's output-token rate.
    pub fn observe_tokens_per_second(&self, model: &str, key_id: &str, rate: f64) {
        let mut state = recover_lock(&self.state);
        state
            .tokens_per_second
            .entry(ModelKeyLabels {
                model: model.to_owned(),
                key_id: key_id.to_owned(),
            })
            .or_insert_with(Histogram::token_rate)
            .observe(rate);
    }

    /// Record numeric usage emitted by the upstream OpenAI-compatible API.
    pub fn add_token_usage(
        &self,
        model: &str,
        key_id: &str,
        token_type: &'static str,
        amount: u64,
    ) {
        let mut state = recover_lock(&self.state);
        let entry = state
            .token_usage
            .entry(TokenUsageLabels {
                model: model.to_owned(),
                key_id: key_id.to_owned(),
                token_type,
            })
            .or_default();
        *entry = entry.saturating_add(amount);
        let labels = ModelKeyLabels {
            model: model.to_owned(),
            key_id: key_id.to_owned(),
        };
        let histogram = match token_type {
            "input" => &mut state.input_tokens_per_request,
            "output" => &mut state.output_tokens_per_request,
            _ => return,
        };
        histogram
            .entry(labels)
            .or_insert_with(Histogram::tokens)
            .observe(u32::try_from(amount).map_or(f64::from(u32::MAX), f64::from));
    }

    /// Record cached input tokens only when the upstream reports that number.
    pub fn add_cache_read_input_tokens(&self, model: &str, key_id: &str, amount: u64) {
        let mut state = recover_lock(&self.state);
        let entry = state
            .cache_read_tokens
            .entry(ModelKeyLabels {
                model: model.to_owned(),
                key_id: key_id.to_owned(),
            })
            .or_default();
        *entry = entry.saturating_add(amount);
    }

    /// Record how many seconds have passed since the last successful key
    /// registry snapshot fetch. The poller calls this on every poll tick.
    pub fn set_key_registry_stale_seconds(&self, seconds: f64) {
        recover_lock(&self.state).key_registry_stale_seconds = seconds;
    }

    /// Count one failed key registry poll under a fixed reason code.
    pub fn record_key_registry_pull_failure(&self, reason: &'static str) {
        let mut state = recover_lock(&self.state);
        *state.key_registry_pull_failures.entry(reason).or_default() += 1;
    }

    /// Record the cached key registry snapshot revision.
    pub fn set_key_registry_revision(&self, revision: i64) {
        recover_lock(&self.state).key_registry_revision = revision;
    }

    /// Record the number of rows the latest snapshot skipped for a pepper
    /// fingerprint mismatch.
    pub fn set_key_registry_pepper_mismatch_rows(&self, rows: u64) {
        recover_lock(&self.state).key_registry_pepper_mismatch_rows = rows;
    }

    /// Count one authenticated request by which key source matched it.
    pub fn record_api_key_accepted(&self, source: &'static str) {
        let mut state = recover_lock(&self.state);
        *state.api_key_accepted.entry(source).or_default() += 1;
    }

    /// Only the contract's bounded `OpenAI` finish reasons are emitted.
    pub fn record_finish_reason(&self, model: &str, reason: &str) {
        let Some(reason) = canonical_finish_reason(reason) else {
            return;
        };
        let mut state = recover_lock(&self.state);
        *state
            .finish_reasons
            .entry(ModelReasonLabels {
                model: model.to_owned(),
                reason,
            })
            .or_default() += 1;
    }
}

fn observe_model_key(
    mutex: &Mutex<MetricsState>,
    map: &mut dyn FnMut(&mut MetricsState) -> &mut BTreeMap<ModelKeyLabels, Histogram>,
    model: &str,
    key_id: &str,
    seconds: f64,
) {
    let mut state = recover_lock(mutex);
    map(&mut state)
        .entry(ModelKeyLabels {
            model: model.to_owned(),
            key_id: key_id.to_owned(),
        })
        .or_default()
        .observe(seconds);
}

fn recover_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn canonical_finish_reason(value: &str) -> Option<&'static str> {
    match value {
        "stop" => Some("stop"),
        "length" => Some("length"),
        "tool_calls" => Some("tool_calls"),
        "content_filter" => Some("content_filter"),
        _ => None,
    }
}

impl MetricsSource for GatewayMetrics {
    #[allow(clippy::too_many_lines)]
    fn render_prometheus(&self) -> String {
        let state = recover_lock(&self.state);
        let mut output = String::new();
        render_header(
            &mut output,
            "gen_ai_server_time_to_first_token",
            "Seconds until the first output token reaches the caller",
            "histogram",
        );
        for (labels, histogram) in &state.ttft {
            render_histogram(
                &mut output,
                "gen_ai_server_time_to_first_token",
                &[("model", &labels.model), ("key_id", &labels.key_id)],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gateway_time_to_first_token_seconds",
            "Caller-visible TTFT classified by reported input-cache reuse",
            "histogram",
        );
        for (labels, histogram) in &state.cache_classified_ttft {
            render_histogram(
                &mut output,
                "gateway_time_to_first_token_seconds",
                &[
                    ("model", &labels.model),
                    ("key_id", &labels.key_id),
                    ("cache_status", labels.cache_status),
                ],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gen_ai_server_time_per_output_token",
            "Seconds between output token deliveries",
            "histogram",
        );
        for (labels, histogram) in &state.output_token_time {
            render_histogram(
                &mut output,
                "gen_ai_server_time_per_output_token",
                &[("model", &labels.model), ("key_id", &labels.key_id)],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gateway_tokens_per_second",
            "Output tokens delivered per second for one streaming request",
            "histogram",
        );
        for (labels, histogram) in &state.tokens_per_second {
            render_histogram(
                &mut output,
                "gateway_tokens_per_second",
                &[("model", &labels.model), ("key_id", &labels.key_id)],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gen_ai_client_token_usage",
            "Tokens reported by the upstream API",
            "counter",
        );
        for (labels, value) in &state.token_usage {
            render_sample(
                &mut output,
                "gen_ai_client_token_usage",
                &[
                    ("model", &labels.model),
                    ("key_id", &labels.key_id),
                    ("type", labels.token_type),
                ],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "gateway_input_tokens_per_request",
            "Input tokens reported for one completed inference request",
            "histogram",
        );
        for (labels, histogram) in &state.input_tokens_per_request {
            render_histogram(
                &mut output,
                "gateway_input_tokens_per_request",
                &[("model", &labels.model), ("key_id", &labels.key_id)],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gateway_output_tokens_per_request",
            "Output tokens reported for one completed inference request",
            "histogram",
        );
        for (labels, histogram) in &state.output_tokens_per_request {
            render_histogram(
                &mut output,
                "gateway_output_tokens_per_request",
                &[("model", &labels.model), ("key_id", &labels.key_id)],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gen_ai_usage_cache_read_input_tokens",
            "Cached input tokens reported by the upstream API",
            "counter",
        );
        for (labels, value) in &state.cache_read_tokens {
            render_sample(
                &mut output,
                "gen_ai_usage_cache_read_input_tokens",
                &[("model", &labels.model), ("key_id", &labels.key_id)],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "gen_ai_response_finish_reasons",
            "OpenAI-compatible completion finish reasons",
            "counter",
        );
        for (labels, value) in &state.finish_reasons {
            render_sample(
                &mut output,
                "gen_ai_response_finish_reasons",
                &[("model", &labels.model), ("reason", labels.reason)],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "gateway_requests",
            "Authenticated inference requests",
            "counter",
        );
        for (labels, value) in &state.requests {
            render_sample(
                &mut output,
                "gateway_requests",
                &[
                    ("model", &labels.model),
                    ("key_id", &labels.key_id),
                    ("status", &labels.status.to_string()),
                ],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "gateway_rejections",
            "Requests rejected before forwarding",
            "counter",
        );
        for (labels, value) in &state.rejections {
            render_sample(
                &mut output,
                "gateway_rejections",
                &[("reason", &labels.reason), ("key_id", &labels.key_id)],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "gateway_upstream_reachable",
            "Whether the model node answers",
            "gauge",
        );
        render_sample(
            &mut output,
            "gateway_upstream_reachable",
            &[],
            &self.environment,
            u64::from(state.upstream_reachable),
        );
        render_header(
            &mut output,
            "gateway_inference_active",
            "Authenticated inference requests currently executing",
            "gauge",
        );
        render_sample(
            &mut output,
            "gateway_inference_active",
            &[],
            &self.environment,
            state.active_requests,
        );
        render_header(
            &mut output,
            "gateway_inference_queue_depth",
            "Authenticated inference requests waiting for execution",
            "gauge",
        );
        render_sample(
            &mut output,
            "gateway_inference_queue_depth",
            &[],
            &self.environment,
            state.queue_depth,
        );
        render_header(
            &mut output,
            "gateway_queue_duration",
            "Seconds spent waiting for an inference execution slot",
            "histogram",
        );
        render_histogram(
            &mut output,
            "gateway_queue_duration",
            &[],
            &state.queue_duration,
            &self.environment,
        );
        render_header(
            &mut output,
            "gateway_request_duration",
            "Caller-visible inference request time in seconds",
            "histogram",
        );
        for (labels, histogram) in &state.request_duration {
            render_histogram(
                &mut output,
                "gateway_request_duration",
                &[
                    ("model", &labels.model),
                    ("status", &labels.status.to_string()),
                ],
                histogram,
                &self.environment,
            );
        }
        render_header(
            &mut output,
            "gateway_key_registry_stale_seconds",
            "Seconds since the last successful key registry snapshot fetch",
            "gauge",
        );
        render_sample_float(
            &mut output,
            "gateway_key_registry_stale_seconds",
            &[],
            &self.environment,
            state.key_registry_stale_seconds,
        );
        render_header(
            &mut output,
            "gateway_key_registry_pull_failures_total",
            "Count of failed key registry snapshot polls by reason",
            "counter",
        );
        for (reason, value) in &state.key_registry_pull_failures {
            render_sample(
                &mut output,
                "gateway_key_registry_pull_failures_total",
                &[("reason", reason)],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "gateway_key_registry_revision",
            "The cached key registry snapshot revision",
            "gauge",
        );
        render_sample(
            &mut output,
            "gateway_key_registry_revision",
            &[],
            &self.environment,
            u64::try_from(state.key_registry_revision).unwrap_or(0),
        );
        render_header(
            &mut output,
            "gateway_key_registry_pepper_mismatch_rows",
            "Rows the latest key registry snapshot skipped for a pepper fingerprint mismatch",
            "gauge",
        );
        render_sample(
            &mut output,
            "gateway_key_registry_pepper_mismatch_rows",
            &[],
            &self.environment,
            state.key_registry_pepper_mismatch_rows,
        );
        render_header(
            &mut output,
            "gateway_api_key_accepted_total",
            "Count of accepted API key authentications by source",
            "counter",
        );
        for (source, value) in &state.api_key_accepted {
            render_sample(
                &mut output,
                "gateway_api_key_accepted_total",
                &[("source", source)],
                &self.environment,
                *value,
            );
        }
        render_header(
            &mut output,
            "confidential_gateway_process_configured",
            "Gateway process passed startup configuration checks",
            "gauge",
        );
        render_sample(
            &mut output,
            "confidential_gateway_process_configured",
            &[],
            &self.environment,
            1,
        );
        output
    }
}

/// Decrements the active-request gauge when the response body ends or closes.
pub struct ActiveRequestGuard {
    metrics: Arc<GatewayMetrics>,
}

impl Drop for ActiveRequestGuard {
    fn drop(&mut self) {
        let mut state = recover_lock(&self.metrics.state);
        state.active_requests = state.active_requests.saturating_sub(1);
    }
}

fn render_header(output: &mut String, name: &str, help: &str, kind: &str) {
    let _ = writeln!(output, "# HELP {name} {help}");
    let _ = writeln!(output, "# TYPE {name} {kind}");
}

fn render_histogram(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    histogram: &Histogram,
    environment: &str,
) {
    for (bucket, value) in histogram.bounds.iter().zip(&histogram.buckets) {
        let mut values = labels.to_vec();
        let bucket_text = bucket.to_string();
        values.push(("le", &bucket_text));
        render_sample(
            output,
            &format!("{name}_bucket"),
            &values,
            environment,
            *value,
        );
    }
    let mut infinity = labels.to_vec();
    infinity.push(("le", "+Inf"));
    render_sample(
        output,
        &format!("{name}_bucket"),
        &infinity,
        environment,
        histogram.count,
    );
    render_sample_float(
        output,
        &format!("{name}_sum"),
        labels,
        environment,
        histogram.sum,
    );
    render_sample(
        output,
        &format!("{name}_count"),
        labels,
        environment,
        histogram.count,
    );
}

fn render_sample(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    environment: &str,
    value: u64,
) {
    render_label_prefix(output, name, labels, environment);
    let _ = writeln!(output, " {value}");
}

fn render_sample_float(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    environment: &str,
    value: f64,
) {
    render_label_prefix(output, name, labels, environment);
    let _ = writeln!(output, " {value}");
}

fn render_label_prefix(
    output: &mut String,
    name: &str,
    labels: &[(&str, &str)],
    environment: &str,
) {
    let _ = write!(output, "{name}{{env=\"{}\"", escape_label(environment));
    for (key, value) in labels {
        let _ = write!(output, ",{key}=\"{}\"", escape_label(value));
    }
    output.push('}');
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[derive(Clone)]
struct MetricsStateRouter {
    source: Arc<dyn MetricsSource>,
}

/// Router for a separate private listener.
pub fn metrics_router(source: Arc<dyn MetricsSource>) -> Router {
    Router::new()
        .route("/metrics", get(metrics))
        .with_state(MetricsStateRouter { source })
}

async fn metrics(
    axum::extract::State(state): axum::extract::State<MetricsStateRouter>,
) -> impl IntoResponse {
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.source.render_prometheus(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_only_contract_metrics_and_safe_labels() {
        let metrics = Arc::new(GatewayMetrics::new("staging"));
        metrics.record_request("deepseek", "key_opaque_01", 200);
        metrics.record_rejection("invalid_api_key");
        metrics.record_key_rejection("revoked_api_key", "key_opaque_02");
        metrics.set_upstream_reachable(true);
        metrics.observe_request_duration("deepseek", 200, 0.25);
        metrics.observe_time_to_first_token("deepseek", "key_opaque_01", 0.1);
        metrics.observe_cache_classified_time_to_first_token(
            "deepseek",
            "key_opaque_01",
            true,
            0.1,
        );
        metrics.observe_cache_classified_time_to_first_token(
            "deepseek",
            "key_opaque_01",
            false,
            0.2,
        );
        metrics.observe_time_per_output_token("deepseek", "key_opaque_01", 0.01);
        metrics.observe_tokens_per_second("deepseek", "key_opaque_01", 100.0);
        metrics.add_token_usage("deepseek", "key_opaque_01", "input", 11);
        metrics.add_token_usage("deepseek", "key_opaque_01", "output", 7);
        metrics.add_cache_read_input_tokens("deepseek", "key_opaque_01", 3);
        metrics.record_finish_reason("deepseek", "stop");
        metrics.record_finish_reason("deepseek", "unbounded-value");
        metrics.enter_queue();
        metrics.leave_queue(0.02);
        let active = metrics.active_request();
        let rendered = metrics.render_prometheus();

        for name in [
            "gen_ai_server_time_to_first_token",
            "gateway_time_to_first_token_seconds",
            "gen_ai_server_time_per_output_token",
            "gateway_tokens_per_second",
            "gen_ai_client_token_usage",
            "gateway_input_tokens_per_request",
            "gateway_output_tokens_per_request",
            "gen_ai_usage_cache_read_input_tokens",
            "gen_ai_response_finish_reasons",
            "gateway_requests",
            "gateway_rejections",
            "gateway_upstream_reachable",
            "gateway_inference_active",
            "gateway_inference_queue_depth",
            "gateway_queue_duration",
            "gateway_request_duration",
            "confidential_gateway_process_configured",
        ] {
            assert!(rendered.contains(name), "missing {name}");
        }
        assert!(rendered.contains("env=\"staging\""));
        assert!(rendered.contains("key_id=\"key_opaque_01\""));
        assert!(rendered.contains("cache_status=\"cached\""));
        assert!(rendered.contains("cache_status=\"cold\""));
        assert!(rendered.contains("reason=\"revoked_api_key\",key_id=\"key_opaque_02\""));
        assert!(rendered.contains("gateway_inference_active{env=\"staging\"} 1"));
        drop(active);
        assert!(
            metrics
                .render_prometheus()
                .contains("gateway_inference_active{env=\"staging\"} 0")
        );
        assert!(!rendered.contains("unbounded-value"));
        assert!(!rendered.contains("prompt"));
        assert!(!rendered.contains("Authorization"));
    }

    #[test]
    fn renders_key_registry_and_source_metrics() {
        let metrics = GatewayMetrics::new("staging");
        metrics.set_key_registry_stale_seconds(12.5);
        metrics.record_key_registry_pull_failure("bad_signature");
        metrics.set_key_registry_revision(42);
        metrics.set_key_registry_pepper_mismatch_rows(2);
        metrics.record_api_key_accepted("local");
        metrics.record_api_key_accepted("registry");
        metrics.record_api_key_accepted("registry");
        let rendered = metrics.render_prometheus();

        for name in [
            "gateway_key_registry_stale_seconds",
            "gateway_key_registry_pull_failures_total",
            "gateway_key_registry_revision",
            "gateway_key_registry_pepper_mismatch_rows",
            "gateway_api_key_accepted_total",
        ] {
            assert!(rendered.contains(name), "missing {name}");
        }
        assert!(rendered.contains("gateway_key_registry_stale_seconds{env=\"staging\"} 12.5"));
        assert!(rendered.contains(
            "gateway_key_registry_pull_failures_total{env=\"staging\",reason=\"bad_signature\"} 1"
        ));
        assert!(rendered.contains("gateway_key_registry_revision{env=\"staging\"} 42"));
        assert!(rendered.contains("gateway_key_registry_pepper_mismatch_rows{env=\"staging\"} 2"));
        assert!(
            rendered.contains("gateway_api_key_accepted_total{env=\"staging\",source=\"local\"} 1")
        );
        assert!(
            rendered
                .contains("gateway_api_key_accepted_total{env=\"staging\",source=\"registry\"} 2")
        );
    }
}
