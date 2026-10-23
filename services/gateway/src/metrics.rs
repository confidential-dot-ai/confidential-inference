//! Privacy-safe Prometheus metrics for the private listener.
//!
//! This module deliberately accepts only fixed metadata and numeric values.
//! It has no API that can receive a prompt, completion, header, or plaintext
//! API key.  The public metric interface is `metrics-contract.md`.

use std::{collections::HashMap, sync::Arc};

use axum::{Router, response::IntoResponse, routing::get};
use prometheus::{
    Gauge, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder, core::Collector,
};

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
const MODEL_KEY: &[&str] = &["model", "key_id"];

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
    registry: Registry,
    requests: IntCounterVec,
    rejections: IntCounterVec,
    upstream_reachable: IntGauge,
    active_requests: IntGauge,
    router_requests: IntGaugeVec,
    queue_depth: IntGauge,
    queue_duration: Histogram,
    request_duration: HistogramVec,
    ttft: HistogramVec,
    cache_classified_ttft: HistogramVec,
    output_token_time: HistogramVec,
    tokens_per_second: HistogramVec,
    token_usage: IntCounterVec,
    input_tokens_per_request: HistogramVec,
    output_tokens_per_request: HistogramVec,
    cache_read_tokens: IntCounterVec,
    finish_reasons: IntCounterVec,
    key_registry_stale_seconds: Gauge,
    key_registry_push_rejections: IntCounterVec,
    key_registry_revision: IntGauge,
    key_registry_pepper_mismatch_rows: IntGauge,
    key_registry_pepper_mismatch: IntGauge,
    key_registry_fetch_failures: IntCounterVec,
    usage_events_dropped: IntCounter,
    usage_events_pending: IntGauge,
    usage_send_failures: IntCounterVec,
    usage_events_rejected: IntCounterVec,
}

/// Metric names, labels and buckets are compile-time constants, so the
/// library can reject them only for a programming error.
fn register<M: Collector + Clone + 'static>(
    registry: &Registry,
    metric: prometheus::Result<M>,
) -> M {
    let metric = metric.unwrap_or_else(|error| unreachable!("invalid metric definition: {error}"));
    registry
        .register(Box::new(metric.clone()))
        .unwrap_or_else(|error| unreachable!("duplicate metric definition: {error}"));
    metric
}

fn counter(registry: &Registry, name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    register(registry, IntCounterVec::new(Opts::new(name, help), labels))
}

fn gauge(registry: &Registry, name: &str, help: &str) -> IntGauge {
    register(registry, IntGauge::new(name, help))
}

fn histogram(registry: &Registry, name: &str, help: &str, buckets: &[f64]) -> Histogram {
    let opts = HistogramOpts::new(name, help).buckets(buckets.to_vec());
    register(registry, Histogram::with_opts(opts))
}

fn histograms(
    registry: &Registry,
    name: &str,
    help: &str,
    buckets: &[f64],
    labels: &[&str],
) -> HistogramVec {
    let opts = HistogramOpts::new(name, help).buckets(buckets.to_vec());
    register(registry, HistogramVec::new(opts, labels))
}

/// Negative and non-finite values come only from clock or upstream errors.
fn observe(histogram: &Histogram, value: f64) {
    if value.is_finite() && value >= 0.0 {
        histogram.observe(value);
    }
}

impl GatewayMetrics {
    /// The process validates this as a DNS-label environment name.
    /// before it builds the registry.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn new(environment: impl Into<String>) -> Self {
        let registry = registry_with_env(environment.into());
        let r = &registry;
        let configured = gauge(
            r,
            "confidential_gateway_process_configured",
            "Gateway process passed startup configuration checks",
        );
        configured.set(1);
        #[cfg(target_os = "linux")]
        registry
            .register(Box::new(
                prometheus::process_collector::ProcessCollector::for_self(),
            ))
            .unwrap_or_else(|error| unreachable!("invalid process collector: {error}"));
        Self {
            requests: counter(
                r,
                "gateway_requests",
                "Authenticated inference requests",
                &["model", "key_id", "status"],
            ),
            rejections: counter(
                r,
                "gateway_rejections",
                "Requests rejected before forwarding",
                &["reason", "key_id"],
            ),
            upstream_reachable: gauge(
                r,
                "gateway_upstream_reachable",
                "Whether the model node answers",
            ),
            active_requests: gauge(
                r,
                "gateway_inference_active",
                "Authenticated inference requests currently executing",
            ),
            router_requests: register(
                r,
                IntGaugeVec::new(
                    Opts::new(
                        "gateway_router_requests_active",
                        "Authenticated requests retaining each router target, including body reads, queues and streams",
                    ),
                    &["router"],
                ),
            ),
            queue_depth: gauge(
                r,
                "gateway_inference_queue_depth",
                "Authenticated inference requests waiting for execution",
            ),
            queue_duration: histogram(
                r,
                "gateway_queue_duration",
                "Seconds spent waiting for an inference execution slot",
                HISTOGRAM_BUCKETS,
            ),
            request_duration: histograms(
                r,
                "gateway_request_duration",
                "Caller-visible inference request time in seconds",
                HISTOGRAM_BUCKETS,
                &["model", "status"],
            ),
            ttft: histograms(
                r,
                "gen_ai_server_time_to_first_token",
                "Seconds until the first output token reaches the caller",
                HISTOGRAM_BUCKETS,
                MODEL_KEY,
            ),
            cache_classified_ttft: histograms(
                r,
                "gateway_time_to_first_token_seconds",
                "Caller-visible TTFT classified by reported input-cache reuse",
                HISTOGRAM_BUCKETS,
                &["model", "key_id", "cache_status"],
            ),
            output_token_time: histograms(
                r,
                "gen_ai_server_time_per_output_token",
                "Seconds between output token deliveries",
                HISTOGRAM_BUCKETS,
                MODEL_KEY,
            ),
            tokens_per_second: histograms(
                r,
                "gateway_tokens_per_second",
                "Output tokens delivered per second for one streaming request",
                TOKEN_RATE_BUCKETS,
                MODEL_KEY,
            ),
            token_usage: counter(
                r,
                "gen_ai_client_token_usage",
                "Tokens reported by the upstream API",
                &["model", "key_id", "type"],
            ),
            input_tokens_per_request: histograms(
                r,
                "gateway_input_tokens_per_request",
                "Input tokens reported for one completed inference request",
                TOKEN_BUCKETS,
                MODEL_KEY,
            ),
            output_tokens_per_request: histograms(
                r,
                "gateway_output_tokens_per_request",
                "Output tokens reported for one completed inference request",
                TOKEN_BUCKETS,
                MODEL_KEY,
            ),
            cache_read_tokens: counter(
                r,
                "gen_ai_usage_cache_read_input_tokens",
                "Cached input tokens reported by the upstream API",
                MODEL_KEY,
            ),
            finish_reasons: counter(
                r,
                "gen_ai_response_finish_reasons",
                "OpenAI-compatible completion finish reasons",
                &["model", "reason"],
            ),
            key_registry_stale_seconds: register(
                r,
                Gauge::new(
                    "gateway_key_registry_stale_seconds",
                    "Seconds since the last applied or acknowledged key registry snapshot",
                ),
            ),
            key_registry_push_rejections: counter(
                r,
                "gateway_key_registry_push_rejected_total",
                "Count of refused key registry snapshot pushes by reason",
                &["reason"],
            ),
            key_registry_revision: gauge(
                r,
                "gateway_key_registry_revision",
                "The key registry snapshot revision this gateway holds",
            ),
            key_registry_pepper_mismatch_rows: gauge(
                r,
                "gateway_key_registry_pepper_mismatch_rows",
                "Rows the latest key registry snapshot skipped for a pepper fingerprint mismatch",
            ),
            key_registry_pepper_mismatch: gauge(
                r,
                "gateway_key_registry_pepper_mismatch",
                "One while the last pushed key registry snapshot named a different pepper than the gateway holds",
            ),
            key_registry_fetch_failures: counter(
                r,
                "gateway_key_registry_fetch_failed_total",
                "Count of failed key snapshot pulls from the admin by reason",
                &["reason"],
            ),
            usage_events_dropped: register(
                r,
                IntCounter::new(
                    "gateway_usage_events_dropped_total",
                    "Usage events dropped because the in-memory queue was full",
                ),
            ),
            usage_events_pending: gauge(
                r,
                "gateway_usage_events_pending",
                "Usage events waiting for the admin to acknowledge them",
            ),
            usage_send_failures: counter(
                r,
                "gateway_usage_send_failed_total",
                "Count of failed usage event batch sends by reason",
                &["reason"],
            ),
            usage_events_rejected: counter(
                r,
                "gateway_usage_events_rejected_total",
                "Usage events dropped because the admin refused them, by HTTP status",
                &["status"],
            ),
            registry,
        }
    }

    /// Every authenticated inference request is counted once, after a status
    /// is known. Authentication failures use [`Self::record_rejection`], so a
    /// fake `key_id` can never enter Prometheus.
    pub fn record_request(&self, model: &str, key_id: &str, status: u16) {
        self.requests
            .with_label_values(&[model, key_id, &status.to_string()])
            .inc();
    }

    /// Record a pre-forwarding rejection with a fixed code, never caller data.
    pub fn record_rejection(&self, reason: &'static str) {
        self.record_key_rejection(reason, "");
    }

    /// Record a rejection for an already known opaque key record ID.
    pub fn record_key_rejection(&self, reason: &'static str, key_id: &str) {
        self.rejections.with_label_values(&[reason, key_id]).inc();
    }

    /// Reflect the outcome of the most recent connection to the model node.
    pub fn set_upstream_reachable(&self, reachable: bool) {
        self.upstream_reachable.set(i64::from(reachable));
    }

    /// Mark one request as waiting for an inference execution slot.
    pub fn enter_queue(&self) {
        self.queue_depth.inc();
    }

    /// Mark one request as no longer waiting and record its bounded wait time.
    pub fn leave_queue(&self, seconds: f64) {
        self.queue_depth.dec();
        observe(&self.queue_duration, seconds);
    }

    /// Hold one active-request gauge slot until the returned guard is dropped.
    #[must_use]
    pub fn active_request(&self) -> GaugeGuard {
        GaugeGuard::new(self.active_requests.clone())
    }

    /// Count an authenticated request from body read through stream close.
    #[must_use]
    pub fn router_request(&self, router: &str) -> GaugeGuard {
        GaugeGuard::new(self.router_requests.with_label_values(&[router]))
    }

    /// Observe caller-visible request time for an authenticated inference call.
    pub fn observe_request_duration(&self, model: &str, status: u16, seconds: f64) {
        observe(
            &self
                .request_duration
                .with_label_values(&[model, &status.to_string()]),
            seconds,
        );
    }

    /// Observe first generated output delivery, not connection setup.
    pub fn observe_time_to_first_token(&self, model: &str, key_id: &str, seconds: f64) {
        observe(&self.ttft.with_label_values(&[model, key_id]), seconds);
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
        let cache_status = if cached { "cached" } else { "cold" };
        observe(
            &self
                .cache_classified_ttft
                .with_label_values(&[model, key_id, cache_status]),
            seconds,
        );
    }

    /// Observe time between generated output deliveries.
    pub fn observe_time_per_output_token(&self, model: &str, key_id: &str, seconds: f64) {
        observe(
            &self.output_token_time.with_label_values(&[model, key_id]),
            seconds,
        );
    }

    /// Observe one completed streaming request's output-token rate.
    pub fn observe_tokens_per_second(&self, model: &str, key_id: &str, rate: f64) {
        observe(
            &self.tokens_per_second.with_label_values(&[model, key_id]),
            rate,
        );
    }

    /// Record numeric usage emitted by the upstream OpenAI-compatible API.
    pub fn add_token_usage(
        &self,
        model: &str,
        key_id: &str,
        token_type: &'static str,
        amount: u64,
    ) {
        self.token_usage
            .with_label_values(&[model, key_id, token_type])
            .inc_by(amount);
        let histogram = match token_type {
            "input" => &self.input_tokens_per_request,
            "output" => &self.output_tokens_per_request,
            _ => return,
        };
        observe(
            &histogram.with_label_values(&[model, key_id]),
            u32::try_from(amount).map_or(f64::from(u32::MAX), f64::from),
        );
    }

    /// Record cached input tokens only when the upstream reports that number.
    pub fn add_cache_read_input_tokens(&self, model: &str, key_id: &str, amount: u64) {
        self.cache_read_tokens
            .with_label_values(&[model, key_id])
            .inc_by(amount);
    }

    /// Record how many seconds have passed since the last applied or
    /// acknowledged key registry snapshot. The key pull loop sets it.
    pub fn set_key_registry_stale_seconds(&self, seconds: f64) {
        self.key_registry_stale_seconds.set(seconds);
    }

    /// Count one refused key registry snapshot push under a fixed reason
    /// code. The admin VM reads the same reason from the response body.
    pub fn record_key_registry_push_rejection(&self, reason: &'static str) {
        self.key_registry_push_rejections
            .with_label_values(&[reason])
            .inc();
    }

    /// Record the cached key registry snapshot revision.
    pub fn set_key_registry_revision(&self, revision: i64) {
        self.key_registry_revision.set(revision.max(0));
    }

    /// Record the number of rows the latest snapshot skipped for a pepper
    /// fingerprint mismatch.
    pub fn set_key_registry_pepper_mismatch_rows(&self, rows: u64) {
        self.key_registry_pepper_mismatch_rows
            .set(i64::try_from(rows).unwrap_or(i64::MAX));
    }

    /// Record whether the last pushed snapshot named a different pepper
    /// than this gateway holds.
    ///
    /// The gauge reads 1 while the two peppers differ and 0 once a
    /// matching snapshot arrives. An alert on this gauge tells an operator
    /// that the admin backend and the gateway hold different peppers, so
    /// no new key can work until one side is corrected.
    pub fn set_key_registry_pepper_mismatch(&self, mismatch: bool) {
        self.key_registry_pepper_mismatch.set(i64::from(mismatch));
    }

    /// Count one failed key snapshot pull under a fixed reason code.
    pub fn record_key_registry_fetch_failure(&self, reason: &'static str) {
        self.key_registry_fetch_failures
            .with_label_values(&[reason])
            .inc();
    }

    /// Count one usage event dropped from a full queue.
    pub fn record_usage_event_dropped(&self) {
        self.usage_events_dropped.inc();
    }

    pub fn set_usage_events_pending(&self, pending: usize) {
        self.usage_events_pending
            .set(i64::try_from(pending).unwrap_or(i64::MAX));
    }

    /// Count one usage event the admin refused and the gateway dropped.
    pub fn record_usage_event_rejected(&self, status: u16) {
        self.usage_events_rejected
            .with_label_values(&[status.to_string()])
            .inc();
    }

    /// Count one failed usage batch send under a fixed reason code.
    pub fn record_usage_send_failure(&self, reason: &'static str) {
        self.usage_send_failures.with_label_values(&[reason]).inc();
    }

    /// Only the contract's bounded `OpenAI` finish reasons are emitted.
    pub fn record_finish_reason(&self, model: &str, reason: &str) {
        let Some(reason) = canonical_finish_reason(reason) else {
            return;
        };
        self.finish_reasons
            .with_label_values(&[model, reason])
            .inc();
    }
}

fn registry_with_env(environment: String) -> Registry {
    Registry::new_custom(None, Some(HashMap::from([("env".to_owned(), environment)])))
        .unwrap_or_else(|error| unreachable!("invalid registry label: {error}"))
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
    fn render_prometheus(&self) -> String {
        let mut output = String::new();
        // Encoding into a String fails only for invalid metric families,
        // which the registry has already rejected at registration.
        let _ = TextEncoder::new().encode_utf8(&self.registry.gather(), &mut output);
        output
    }
}

/// Decrements a gauge when the request, or its response body, ends.
pub struct GaugeGuard(IntGauge);

impl GaugeGuard {
    fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        Self(gauge)
    }
}

impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
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
        assert!(rendered.contains("key_id=\"key_opaque_02\",reason=\"revoked_api_key\""));
        assert!(rendered.contains(
            "gateway_requests{key_id=\"key_opaque_01\",model=\"deepseek\",status=\"200\",env=\"staging\"} 1\n"
        ));
        assert!(rendered.contains(
            "gateway_request_duration_bucket{model=\"deepseek\",status=\"200\",env=\"staging\",le=\"1\"} 1\n"
        ));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn renders_process_metrics() {
        let rendered = GatewayMetrics::new("staging").render_prometheus();
        assert!(rendered.contains("process_resident_memory_bytes{env=\"staging\"}"));
    }

    #[test]
    fn renders_key_registry_and_source_metrics() {
        let metrics = GatewayMetrics::new("staging");
        metrics.set_key_registry_stale_seconds(12.5);
        metrics.record_key_registry_push_rejection("stale_revision");
        metrics.set_key_registry_revision(42);
        metrics.set_key_registry_pepper_mismatch_rows(2);
        metrics.set_key_registry_pepper_mismatch(true);
        metrics.record_key_registry_fetch_failure("unreachable");
        let rendered = metrics.render_prometheus();

        for name in [
            "gateway_key_registry_stale_seconds",
            "gateway_key_registry_push_rejected_total",
            "gateway_key_registry_revision",
            "gateway_key_registry_pepper_mismatch_rows",
            "gateway_key_registry_pepper_mismatch",
            "gateway_key_registry_fetch_failed_total",
        ] {
            assert!(rendered.contains(name), "missing {name}");
        }
        assert!(rendered.contains("gateway_key_registry_stale_seconds{env=\"staging\"} 12.5"));
        assert!(rendered.contains(
            "gateway_key_registry_push_rejected_total{reason=\"stale_revision\",env=\"staging\"} 1"
        ));
        assert!(rendered.contains("gateway_key_registry_revision{env=\"staging\"} 42"));
        assert!(rendered.contains("gateway_key_registry_pepper_mismatch_rows{env=\"staging\"} 2"));
        assert!(rendered.contains("gateway_key_registry_pepper_mismatch{env=\"staging\"} 1"));
        metrics.set_key_registry_pepper_mismatch(false);
        assert!(
            metrics
                .render_prometheus()
                .contains("gateway_key_registry_pepper_mismatch{env=\"staging\"} 0")
        );
        assert!(rendered.contains(
            "gateway_key_registry_fetch_failed_total{reason=\"unreachable\",env=\"staging\"} 1"
        ));
    }
}
