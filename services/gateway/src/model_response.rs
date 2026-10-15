//! Keep internal model aliases out of public completion responses.
use crate::usage::Observation;
use serde_json::Value;
use std::io;

const MAXIMUM_PENDING_BYTES: usize = 16 * 1024 * 1024;

fn rewrite_value(mut value: Value, model: &str) -> io::Result<Vec<u8>> {
    if let Some(name) = value.get_mut("model") {
        *name = Value::String(model.to_owned());
    }
    serde_json::to_vec(&value).map_err(io::Error::other)
}

// These flags describe independent wire-format and accounting state.
#[allow(clippy::struct_excessive_bools)]
pub(crate) struct ModelResponse {
    model: String,
    event_stream: bool,
    pending: Vec<u8>,
    observation: Observation,
    hide_final_usage: bool,
    stream_done: bool,
    expected_model: Option<String>,
    model_mismatch: bool,
}

impl ModelResponse {
    pub(crate) fn new(model: String, event_stream: bool) -> Self {
        Self {
            model,
            event_stream,
            pending: Vec::new(),
            observation: Observation::default(),
            hide_final_usage: false,
            stream_done: false,
            expected_model: None,
            model_mismatch: false,
        }
    }

    pub(crate) fn hide_final_usage(mut self, hide: bool) -> Self {
        self.hide_final_usage = hide;
        self
    }

    pub(crate) fn observation(&self) -> Observation {
        self.observation
    }
    pub(crate) fn expected_model(mut self, model: Option<String>) -> Self {
        self.expected_model = model;
        self
    }
    pub(crate) fn stream_done(&self) -> bool {
        self.stream_done
    }

    fn observe(&mut self, value: &Value, final_usage: bool) {
        if self.expected_model.as_ref().is_some_and(|expected| {
            value.get("model").and_then(Value::as_str) != Some(expected.as_str())
        }) {
            if !self.model_mismatch {
                tracing::warn!("usage model identity did not match its approved binding");
            }
            self.model_mismatch = true;
        }
        if self.model_mismatch {
            self.observation = Observation::default();
            return;
        }
        if let Some(usage) = value.get("usage").filter(|v| v.is_object()) {
            let number = |field: &str| {
                usage
                    .get(field)
                    .and_then(Value::as_u64)
                    .filter(|n| *n <= 9_007_199_254_740_991)
            };
            // Replace cumulative observations. A final aggregate supersedes
            // all per-choice intermediate messages.
            self.observation = Observation {
                input: number("prompt_tokens"),
                output: number("completion_tokens"),
                cached: usage
                    .get("prompt_tokens_details")
                    .and_then(|d| {
                        if d.is_null() {
                            Some(0)
                        } else {
                            d.get("cached_tokens").and_then(Value::as_u64)
                        }
                    })
                    .or_else(|| number("cache_read_input_tokens"))
                    .filter(|n| *n <= 9_007_199_254_740_991),
                reasoning: number("reasoning_tokens")
                    .or_else(|| {
                        usage
                            .get("completion_tokens_details")
                            .and_then(|d| d.get("reasoning_tokens"))
                            .and_then(Value::as_u64)
                    })
                    .filter(|n| *n <= 9_007_199_254_740_991),
                final_usage,
            };
            if self
                .observation
                .cached
                .zip(self.observation.input)
                .is_some_and(|(a, b)| a > b)
            {
                self.observation.cached = None;
            }
            if self.observation.input.is_none() {
                self.observation.cached = None;
            }
            if self
                .observation
                .reasoning
                .zip(self.observation.output)
                .is_some_and(|(a, b)| a > b)
            {
                self.observation.reasoning = None;
            }
            if self.observation.output.is_none() {
                self.observation.reasoning = None;
            }
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        if self.event_stream {
            // Process lines as they arrive, including split UTF-8 and CRLF.
            for segment in bytes.split_inclusive(|byte| *byte == b'\n') {
                self.append(segment)?;
                if self.pending.last() == Some(&b'\n') {
                    output.extend(self.line()?);
                    self.pending.clear();
                }
            }
        } else {
            self.append(bytes)?;
        }
        Ok(output)
    }

    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.pending.len().saturating_add(bytes.len()) > MAXIMUM_PENDING_BYTES {
            return Err(io::Error::other(
                "upstream completion exceeds response limit",
            ));
        }
        self.pending.extend_from_slice(bytes);
        Ok(())
    }

    fn line(&mut self) -> io::Result<Vec<u8>> {
        let Some(data) = self.pending.strip_prefix(b"data:") else {
            return Ok(self.pending.clone());
        };
        let data = data.strip_prefix(b" ").unwrap_or(data);
        let payload = data.strip_suffix(b"\n").unwrap_or(data);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        if payload == b"[DONE]" {
            self.stream_done = true;
            return Ok(self.pending.clone());
        }
        if payload.is_empty() {
            return Ok(self.pending.clone());
        }
        let value: Value = serde_json::from_slice(payload)
            .map_err(|_| io::Error::other("invalid upstream completion JSON"))?;
        let final_usage = value
            .get("choices")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
            && value.get("usage").is_some_and(Value::is_object);
        self.observe(&value, final_usage);
        if final_usage && self.hide_final_usage {
            return Ok(Vec::new());
        }
        let rewritten = rewrite_value(value, &self.model)?;
        let mut output = b"data: ".to_vec();
        output.extend(rewritten);
        if self.pending.ends_with(b"\r\n") {
            output.extend(b"\r\n");
        } else if self.pending.ends_with(b"\n") {
            output.push(b'\n');
        }
        Ok(output)
    }

    pub(crate) fn finish(&mut self) -> io::Result<Vec<u8>> {
        if self.event_stream {
            self.line()
        } else {
            let value: Value = serde_json::from_slice(&self.pending)
                .map_err(|_| io::Error::other("invalid upstream completion JSON"))?;
            self.observe(&value, true);
            rewrite_value(value, &self.model)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_preserves_content_usage_and_other_fields() {
        let mut response = ModelResponse::new("public".into(), false);
        let original = json!({"model":"backend-version", "choices":[{"message":{"content":"hello"},"finish_reason":"stop"}],"usage":{"completion_tokens":2},"id":"same"});
        let bytes = serde_json::to_vec(&original).unwrap();
        for chunk in bytes.chunks(3) {
            assert!(response.push(chunk).unwrap().is_empty());
        }
        let actual: Value = serde_json::from_slice(&response.finish().unwrap()).unwrap();
        let mut expected = original;
        expected["model"] = json!("public");
        assert_eq!(actual, expected);
    }

    #[test]
    fn stream_preserves_split_unicode_comments_usage_and_done() {
        let input = "data: {\"model\":\"backend\",\"choices\":[{\"delta\":{\"content\":\"日\"}}]}\r\n\r\n: heartbeat\n\ndata: {\"model\":\"backend\",\"choices\":[],\"usage\":{\"completion_tokens\":1}}\n\ndata: [DONE]\n\n";
        let mut response = ModelResponse::new("public".into(), true);
        let mut output = Vec::new();
        for byte in input.as_bytes() {
            output.extend(response.push(&[*byte]).unwrap());
        }
        output.extend(response.finish().unwrap());
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("backend"));
        assert!(text.contains("日"));
        assert!(text.contains(": heartbeat\n\n"));
        assert!(text.ends_with("data: [DONE]\n\n"));
        assert_eq!(text.matches("\"model\":\"public\"").count(), 2);
        assert!(text.contains("\"completion_tokens\":1"));
    }

    #[test]
    fn bounded_invalid_response_fails() {
        let mut response = ModelResponse::new("public".into(), false);
        assert!(response.push(&vec![0; MAXIMUM_PENDING_BYTES + 1]).is_err());
        let mut response = ModelResponse::new("public".into(), true);
        assert!(response.push(b"data: invalid\n").is_err());
    }

    #[test]
    fn final_usage_replaces_intermediate_totals_and_hidden_frame_stays_private() {
        let data = "data: {\"model\":\"backend\",\"choices\":[{\"delta\":{\"content\":\"日\"}}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2}}\n\ndata:{\"model\":\"backend\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":4},\"reasoning_tokens\":2}}\n\ndata: [DONE]\n\n";
        let mut response = ModelResponse::new("public".into(), true).hide_final_usage(true);
        let mut output = Vec::new();
        for chunk in data.as_bytes().chunks(1) {
            output.extend(response.push(chunk).unwrap());
        }
        output.extend(response.finish().unwrap());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("日"));
        assert!(text.contains("[DONE]"));
        assert!(!text.contains("\"completion_tokens\":5"));
        assert_eq!(response.observation().input, Some(10));
        assert_eq!(response.observation().output, Some(5));
        assert_eq!(response.observation().cached, Some(4));
        assert_eq!(response.observation().reasoning, Some(2));
        assert!(response.observation().final_usage);
        assert!(response.stream_done());
    }

    #[test]
    fn usage_survives_a_response_larger_than_the_old_metric_buffer() {
        let mut response = ModelResponse::new("public".into(), false);
        let body = serde_json::to_vec(&json!({"model":"backend", "choices":[{"message":{"content":"x".repeat(1_100_000)}}],"usage":{"prompt_tokens":10,"completion_tokens":500}})).unwrap();
        for chunk in body.chunks(4096) {
            response.push(chunk).unwrap();
        }
        response.finish().unwrap();
        assert_eq!(response.observation().output, Some(500));
        assert!(response.observation().final_usage);
    }

    #[test]
    fn an_unapproved_backend_model_cannot_supply_attributed_usage() {
        let mut response = ModelResponse::new("public".into(), false)
            .expected_model(Some("approved-backend".into()));
        response.push(br#"{"model":"unapproved-backend","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}"#).unwrap();
        response.finish().unwrap();
        assert!(response.observation().input.is_none());
        assert!(!response.observation().final_usage);
    }
}
