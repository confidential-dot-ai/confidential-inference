//! Metrics consume decoded values and the same bounded numeric observations
//! as usage accounting. This module never reads or retains response bytes.
use crate::{metrics::GatewayMetrics, model_response::Wire, usage::Observation};
use serde_json::Value;
use std::time::Instant;

pub(crate) struct ResponseMetrics {
    wire: Wire,
    usage: Observation,
    first_output_at: Option<Instant>,
    last_output_at: Option<Instant>,
    ttft_seconds: Option<f64>,
}

impl ResponseMetrics {
    pub(crate) fn new(wire: Wire) -> Self {
        Self {
            wire,
            usage: Observation::default(),
            first_output_at: None,
            last_output_at: None,
            ttft_seconds: None,
        }
    }
    pub(crate) fn observe(
        &mut self,
        value: &Value,
        usage: Observation,
        metrics: &GatewayMetrics,
        model: &str,
        key_id: &str,
        started: Instant,
    ) {
        // Counts are cumulative. Replace them and publish once on stream end.
        self.usage = usage;
        let output = match self.wire {
            Wire::Completions => {
                record_finish_reasons(metrics, model, value);
                has_output_delta(value)
            }
            Wire::Responses => {
                let response = value.get("response").unwrap_or(value);
                if let Some(reason) = responses_finish_reason(response) {
                    metrics.record_finish_reason(model, reason);
                }
                has_responses_output_delta(value)
            }
        };
        if output {
            let now = Instant::now();
            if let Some(previous) = self.last_output_at.replace(now) {
                metrics.observe_time_per_output_token(
                    model,
                    key_id,
                    now.duration_since(previous).as_secs_f64(),
                );
            } else {
                self.first_output_at = Some(now);
                let seconds = started.elapsed().as_secs_f64();
                self.ttft_seconds = Some(seconds);
                metrics.observe_time_to_first_token(model, key_id, seconds);
            }
        }
    }
    pub(crate) fn finish(&self, metrics: &GatewayMetrics, model: &str, key_id: &str) {
        for (kind, count) in [("input", self.usage.input), ("output", self.usage.output)] {
            if let Some(count) = count {
                metrics.add_token_usage(model, key_id, kind, count);
            }
        }
        if let Some(count) = self.usage.cached {
            metrics.add_cache_read_input_tokens(model, key_id, count);
        }
        if let (Some(ttft), Some(cached)) = (self.ttft_seconds, self.usage.cached) {
            metrics.observe_cache_classified_time_to_first_token(model, key_id, cached > 0, ttft);
        }
        if let (Some(tokens), Some(first), Some(last)) =
            (self.usage.output, self.first_output_at, self.last_output_at)
        {
            let seconds = last.duration_since(first).as_secs_f64();
            if tokens > 1 && seconds > 0.0 {
                let generated = u32::try_from(tokens - 1).map_or(f64::from(u32::MAX), f64::from);
                metrics.observe_tokens_per_second(model, key_id, generated / seconds);
            }
        }
    }
}

fn responses_finish_reason(response: &Value) -> Option<&'static str> {
    match response.get("status").and_then(Value::as_str)? {
        "completed" => {
            let calls_a_tool = response
                .get("output")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        matches!(
                            item.get("type").and_then(Value::as_str),
                            Some("function_call" | "custom_tool_call")
                        )
                    })
                });
            Some(if calls_a_tool { "tool_calls" } else { "stop" })
        }
        "incomplete" => match response
            .get("incomplete_details")
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str)
        {
            Some("max_output_tokens") => Some("length"),
            Some("content_filter") => Some("content_filter"),
            _ => None,
        },
        _ => None,
    }
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

/// A Responses API text or reasoning delta with text in it.
fn has_responses_output_delta(value: &Value) -> bool {
    matches!(
        value.get("type").and_then(Value::as_str),
        Some(
            "response.output_text.delta"
                | "response.reasoning_text.delta"
                | "response.reasoning_summary_text.delta"
        )
    ) && value
        .get("delta")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{metrics::MetricsSource, model_response::ModelResponse};
    use serde_json::json;

    fn sample(text: &str, name: &str, label: &str) -> u64 {
        text.lines()
            .find(|line| line.starts_with(name) && line.contains(label))
            .unwrap()
            .rsplit_once(' ')
            .unwrap()
            .1
            .parse()
            .unwrap()
    }

    #[test]
    fn shared_decode_preserves_split_utf8_and_counts_cumulative_usage_once() {
        let metrics = GatewayMetrics::new("test");
        let mut facts = ResponseMetrics::new(Wire::Completions);
        let mut response = ModelResponse::new("public".into(), true);
        let input = concat!(
            "data: {\"model\":\"backend\",\"choices\":[{\"delta\":{\"content\":\"日\"}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":1}}\r\n\r\n",
            "data: {\"model\":\"backend\",\"choices\":[{\"delta\":{\"content\":\"private\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\n",
            "data: {\"model\":\"backend\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\n",
            "data: [DONE]\n\n"
        );
        let started = Instant::now();
        let mut observe =
            |v: &Value, usage| facts.observe(v, usage, &metrics, "public", "key", started);
        for byte in input.as_bytes() {
            response.push_observed(&[*byte], &mut observe).unwrap();
        }
        response.finish_observed(&mut observe).unwrap();
        facts.finish(&metrics, "public", "key");
        let text = metrics.render_prometheus();
        assert_eq!(
            sample(&text, "gen_ai_client_token_usage{", "type=\"input\""),
            10
        );
        assert_eq!(
            sample(&text, "gen_ai_client_token_usage{", "type=\"output\""),
            2
        );
        assert_eq!(
            sample(
                &text,
                "gateway_input_tokens_per_request_count{",
                "key_id=\"key\""
            ),
            1
        );
        assert_eq!(
            sample(
                &text,
                "gen_ai_server_time_to_first_token_count{",
                "key_id=\"key\""
            ),
            1
        );
        assert_eq!(
            sample(
                &text,
                "gen_ai_usage_cache_read_input_tokens{",
                "key_id=\"key\""
            ),
            4
        );
        assert!(!text.contains("private"));
    }

    #[test]
    fn model_identity_and_numeric_bounds_are_shared_with_metrics() {
        for (model, usage) in [
            (
                "approved",
                json!({"prompt_tokens":-1,"completion_tokens":9_007_199_254_740_992_u64}),
            ),
            ("wrong", json!({"prompt_tokens":10,"completion_tokens":2})),
        ] {
            let metrics = GatewayMetrics::new("test");
            let mut facts = ResponseMetrics::new(Wire::Completions);
            let mut response =
                ModelResponse::new("public".into(), false).expected_model(Some("approved".into()));
            let body = json!({"model":model,"choices":[],"usage":usage}).to_string();
            response.push(body.as_bytes()).unwrap();
            response
                .finish_observed(&mut |v, observation| {
                    facts.observe(v, observation, &metrics, "public", "key", Instant::now());
                })
                .unwrap();
            facts.finish(&metrics, "public", "key");
            assert!(
                !metrics
                    .render_prometheus()
                    .contains("gen_ai_client_token_usage{")
            );
        }
    }

    #[test]
    fn large_json_responses_keep_their_numeric_metrics() {
        let metrics = GatewayMetrics::new("test");
        let mut facts = ResponseMetrics::new(Wire::Completions);
        let mut response = ModelResponse::new("public".into(), false);
        let body = json!({"model":"backend","choices":[{"message":{"content":"x".repeat(1_100_000)},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"prompt_tokens_details":null}}).to_string();
        for chunk in body.as_bytes().chunks(4096) {
            response.push(chunk).unwrap();
        }
        response
            .finish_observed(&mut |v, observation| {
                facts.observe(v, observation, &metrics, "public", "key", Instant::now());
            })
            .unwrap();
        facts.finish(&metrics, "public", "key");
        let text = metrics.render_prometheus();
        assert_eq!(
            sample(&text, "gen_ai_client_token_usage{", "type=\"input\""),
            10
        );
        assert_eq!(
            sample(
                &text,
                "gen_ai_usage_cache_read_input_tokens{",
                "key_id=\"key\""
            ),
            0
        );
    }
}
