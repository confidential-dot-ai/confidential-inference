//! Keep internal model aliases out of public completion responses.
use serde_json::Value;
use std::io;

const MAXIMUM_PENDING_BYTES: usize = 16 * 1024 * 1024;

fn rewrite_json(bytes: &[u8], model: &str) -> io::Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(bytes)
        .map_err(|_| io::Error::other("invalid upstream completion JSON"))?;
    if let Some(name) = value.get_mut("model") {
        *name = Value::String(model.to_owned());
    }
    serde_json::to_vec(&value).map_err(io::Error::other)
}

pub(crate) struct ModelResponse {
    model: String,
    event_stream: bool,
    pending: Vec<u8>,
}

impl ModelResponse {
    pub(crate) fn new(model: String, event_stream: bool) -> Self {
        Self {
            model,
            event_stream,
            pending: Vec::new(),
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

    fn line(&self) -> io::Result<Vec<u8>> {
        let Some(data) = self.pending.strip_prefix(b"data:") else {
            return Ok(self.pending.clone());
        };
        let data = data.strip_prefix(b" ").unwrap_or(data);
        let payload = data.strip_suffix(b"\n").unwrap_or(data);
        let payload = payload.strip_suffix(b"\r").unwrap_or(payload);
        if payload == b"[DONE]" || payload.is_empty() {
            return Ok(self.pending.clone());
        }
        let mut output = b"data: ".to_vec();
        output.extend(rewrite_json(payload, &self.model)?);
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
            rewrite_json(&self.pending, &self.model)
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
}
