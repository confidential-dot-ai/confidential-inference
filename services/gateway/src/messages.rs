//! Translate the Messages API at the gateway boundary. The inference router
//! receives only Chat Completions. No conversation state survives a request.
use std::{collections::BTreeMap, io};

use crate::{inference_api::ErrorCode, model_response::Output, usage::Observation};
use axum::{
    Json,
    body::Body,
    http::{Response, StatusCode, header},
    response::IntoResponse,
};
use serde_json::{Value, json};

type Invalid = &'static str;

fn text(value: &Value, field: &str) -> Result<String, Invalid> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or("invalid_messages_request")
}

fn text_blocks(value: &Value) -> Result<String, Invalid> {
    if let Some(s) = value.as_str() {
        return Ok(s.to_owned());
    }
    let mut result = String::new();
    for block in value.as_array().ok_or("invalid_messages_content")? {
        if block["type"] != "text" {
            return Err("unsupported_messages_content");
        }
        result.push_str(block["text"].as_str().ok_or("invalid_messages_content")?);
    }
    Ok(result)
}

fn content_part(block: &Value) -> Result<Value, Invalid> {
    match block["type"].as_str() {
        Some("text") => Ok(
            json!({"type":"text", "text":block["text"].as_str().ok_or("invalid_messages_content")?}),
        ),
        Some("image") => {
            let source = &block["source"];
            let url = match source["type"].as_str() {
                Some("url") => text(source, "url")?,
                Some("base64") => {
                    let media = text(source, "media_type")?;
                    if !matches!(
                        media.as_str(),
                        "image/jpeg" | "image/png" | "image/gif" | "image/webp"
                    ) {
                        return Err("unsupported_messages_image");
                    }
                    format!("data:{media};base64,{}", text(source, "data")?)
                }
                _ => return Err("unsupported_messages_image"),
            };
            Ok(json!({"type":"image_url", "image_url":{"url":url}}))
        }
        _ => Err("unsupported_messages_content"),
    }
}

fn tool_content(value: &Value) -> Result<Value, Invalid> {
    if value.is_string() {
        return Ok(value.clone());
    }
    value
        .as_array()
        .ok_or("invalid_tool_result")?
        .iter()
        .map(content_part)
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn flush_content(messages: &mut Vec<Value>, role: &str, parts: &mut Vec<Value>) {
    if !parts.is_empty() {
        messages.push(json!({"role":role, "content":std::mem::take(parts)}));
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn request(payload: &Value) -> Result<Value, Invalid> {
    let object = payload.as_object().ok_or("invalid_messages_request")?;
    // Refuse features that cannot be represented by this backend. Do not
    // silently discard a caller's control fields or retain their values.
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "model"
                | "messages"
                | "max_tokens"
                | "system"
                | "stream"
                | "temperature"
                | "top_p"
                | "top_k"
                | "stop_sequences"
                | "tools"
                | "tool_choice"
                | "metadata"
        ) {
            return Err("unsupported_messages_field");
        }
    }
    let maximum = payload["max_tokens"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("max_tokens_required")?;
    let stream = match payload.get("stream") {
        None => false,
        Some(value) => value.as_bool().ok_or("invalid_messages_stream")?,
    };
    let mut messages = Vec::new();
    if let Some(system) = payload.get("system") {
        messages.push(json!({"role":"system", "content":text_blocks(system)?}));
    }
    let turns = payload["messages"]
        .as_array()
        .filter(|v| !v.is_empty())
        .ok_or("messages_required")?;
    for turn in turns {
        let role = text(turn, "role")?;
        if !matches!(role.as_str(), "user" | "assistant") {
            return Err("invalid_messages_role");
        }
        let content = &turn["content"];
        if content.is_string() {
            messages.push(json!({"role":role,"content":content}));
            continue;
        }
        let mut parts = Vec::new();
        let mut calls = Vec::new();
        for block in content.as_array().ok_or("invalid_messages_content")? {
            match block["type"].as_str() {
                Some("tool_use") if role == "assistant" => {
                    if !block["input"].is_object() {
                        return Err("invalid_tool_input");
                    }
                    calls.push(json!({"id":text(block,"id")?,"type":"function","function":{"name":text(block,"name")?,"arguments":block["input"].to_string()}}));
                }
                Some("tool_result") if role == "user" => {
                    flush_content(&mut messages, &role, &mut parts);
                    let mut content = tool_content(block.get("content").unwrap_or(&json!("")))?;
                    if block["is_error"] == true {
                        content = match content {
                            Value::String(s) => json!(format!("[Tool error] {s}")),
                            Value::Array(mut parts) => {
                                parts.insert(0, json!({"type":"text","text":"[Tool error]"}));
                                json!(parts)
                            }
                            _ => unreachable!(),
                        };
                    }
                    messages.push(json!({"role":"tool","tool_call_id":text(block,"tool_use_id")?,"content":content}));
                }
                _ => parts.push(content_part(block)?),
            }
        }
        if calls.is_empty() {
            flush_content(&mut messages, &role, &mut parts);
        } else {
            messages.push(json!({"role":role,"content":parts,"tool_calls":calls}));
        }
    }
    let mut result = json!({"model":text(payload,"model")?,"messages":messages,"max_tokens":maximum,"stream":stream});
    for key in ["temperature", "top_p", "top_k"] {
        if let Some(value) = payload.get(key) {
            result[key] = value.clone();
        }
    }
    if let Some(value) = payload.get("stop_sequences") {
        if !value
            .as_array()
            .is_some_and(|v| v.iter().all(Value::is_string))
        {
            return Err("invalid_stop_sequences");
        }
        result["stop"] = value.clone();
    }
    if let Some(tools) = payload.get("tools") {
        let tools = tools.as_array().ok_or("invalid_messages_tools")?;
        let mut converted = Vec::new();
        for tool in tools {
            if tool.get("type").is_some_and(|v| v != "custom") {
                return Err("unsupported_messages_tool");
            }
            if !tool["input_schema"].is_object() {
                return Err("invalid_tool_schema");
            }
            let mut function = json!({"name":text(tool,"name")?,"parameters":tool["input_schema"]});
            if let Some(description) = tool.get("description") {
                function["description"] = description.clone();
            }
            converted.push(json!({"type":"function","function":function}));
        }
        result["tools"] = json!(converted);
    }
    if let Some(choice) = payload.get("tool_choice") {
        result["tool_choice"] = match choice["type"].as_str() {
            Some("auto") => json!("auto"),
            Some("any") => json!("required"),
            Some("none") => json!("none"),
            Some("tool") => json!({"type":"function","function":{"name":text(choice,"name")?}}),
            _ => return Err("invalid_messages_tool_choice"),
        };
        if let Some(disable) = choice.get("disable_parallel_tool_use") {
            result["parallel_tool_calls"] =
                json!(!disable.as_bool().ok_or("invalid_messages_tool_choice")?);
        }
    }
    // metadata identifies the caller for some providers. This service keeps
    // no customer metadata and does not send it to the worker.
    Ok(result)
}

fn invalid_upstream() -> io::Error {
    io::Error::other("invalid upstream Messages response")
}

fn stop_reason(reason: &str) -> Result<&'static str, io::Error> {
    match reason {
        "stop" => Ok("end_turn"),
        "length" => Ok("max_tokens"),
        "tool_calls" => Ok("tool_use"),
        "content_filter" => Ok("refusal"),
        _ => Err(invalid_upstream()),
    }
}

fn usage(value: Observation) -> Value {
    let input = value.input.unwrap_or(0);
    let cached = value.cached.unwrap_or(0).min(input);
    json!({"input_tokens":input-cached,"output_tokens":value.output.unwrap_or(0),"cache_read_input_tokens":cached,"cache_creation_input_tokens":0})
}

fn message(value: &Value, observation: Observation) -> io::Result<Value> {
    let choice = value["choices"].get(0).ok_or_else(invalid_upstream)?;
    let mut content = Vec::new();
    if let Some(text) = choice["message"]["content"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        content.push(json!({"type":"text","text":text}));
    }
    if let Some(calls) = choice["message"]["tool_calls"].as_array() {
        for call in calls {
            let input: Value = serde_json::from_str(
                call["function"]["arguments"]
                    .as_str()
                    .ok_or_else(invalid_upstream)?,
            )
            .map_err(|_| invalid_upstream())?;
            if !input.is_object() {
                return Err(invalid_upstream());
            }
            content.push(json!({"type":"tool_use","id":call["id"].as_str().ok_or_else(invalid_upstream)?,"name":call["function"]["name"].as_str().ok_or_else(invalid_upstream)?,"input":input}));
        }
    }
    Ok(
        json!({"id":format!("msg_{}",uuid::Uuid::new_v4().simple()),"type":"message","role":"assistant","model":value["model"],"content":content,"stop_reason":if choice["matched_stop"].is_string() { "stop_sequence" } else { stop_reason(choice["finish_reason"].as_str().ok_or_else(invalid_upstream)?)? },"stop_sequence":choice["matched_stop"].as_str(),"usage":usage(observation)}),
    )
}

fn error(status: StatusCode) -> Value {
    let kind = match status.as_u16() {
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        500..=599 => "api_error",
        _ => "invalid_request_error",
    };
    json!({"type":"error","error":{"type":kind,"message":status.canonical_reason().unwrap_or("Request failed")}})
}

/// JSON output is already decoded and serialized by the shared pipeline.
/// Wait for it so a failed conversion can return an HTTP error before headers.
pub(crate) async fn complete_json(response: Response<Body>) -> Response<Body> {
    if !response.status().is_success()
        || response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/event-stream"))
    {
        return response;
    }
    if !response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
    {
        return crate::client_error(StatusCode::BAD_GATEWAY, "invalid_upstream_response");
    }
    let (parts, body) = response.into_parts();
    match axum::body::to_bytes(body, crate::model_response::MAXIMUM_PENDING_BYTES).await {
        Ok(bytes) => Response::from_parts(parts, Body::from(bytes)),
        Err(_) => crate::client_error(StatusCode::BAD_GATEWAY, "invalid_upstream_response"),
    }
}

/// Fixed errors already carry their code. Do not parse a response body.
pub(crate) fn error_response(response: Response<Body>) -> Response<Body> {
    let (mut parts, _) = response.into_parts();
    let mut value = error(parts.status);
    if let Some(code) = parts.extensions.get::<ErrorCode>() {
        value["error"]["message"] = json!(code.0);
    }
    parts.headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    Response::from_parts(parts, Json(value).into_response().into_body())
}

/// Receives values from the shared upstream decoder, after model rewriting.
#[derive(Default)]
pub(crate) struct MessagesOutput {
    stream: Stream,
    streaming: bool,
}

impl MessagesOutput {
    pub(crate) fn new(streaming: bool) -> Self {
        Self {
            streaming,
            stream: Stream::default(),
        }
    }
}

impl Output for MessagesOutput {
    fn value(
        &mut self,
        value: Value,
        observation: Observation,
        streaming: bool,
        _: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.streaming = streaming;
        if streaming {
            if self.stream.done {
                return Ok(Vec::new());
            }
            self.stream.value(&value, observation)
        } else {
            serde_json::to_vec(&message(&value, observation)?).map_err(io::Error::other)
        }
    }
    fn raw(&mut self, _: &[u8]) -> io::Result<Vec<u8>> {
        Ok(Vec::new())
    }
    fn done(&mut self, _: &[u8]) -> io::Result<Vec<u8>> {
        self.stream.finish()
    }
    fn finish(&mut self) -> io::Result<Vec<u8>> {
        if self.streaming && !self.stream.done {
            return Err(invalid_upstream());
        }
        Ok(Vec::new())
    }
    fn failure(&mut self, _: io::Error) -> io::Result<Vec<u8>> {
        if self.streaming {
            Ok(event("error", &error(StatusCode::BAD_GATEWAY)))
        } else {
            Err(invalid_upstream())
        }
    }
}

fn event(kind: &str, payload: &Value) -> Vec<u8> {
    format!("event: {kind}\ndata: {payload}\n\n").into_bytes()
}

#[derive(Default)]
struct Tool {
    index: Option<usize>,
    id: String,
    name: String,
}

#[derive(Default)]
struct Stream {
    started: bool,
    done: bool,
    next_index: usize,
    text_index: Option<usize>,
    tools: BTreeMap<u64, Tool>,
    reason: Option<String>,
    matched_stop: Option<String>,
    usage: Observation,
}

impl Stream {
    fn value(&mut self, value: &Value, observation: Observation) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        if !self.started {
            let model = value["model"].as_str().ok_or_else(invalid_upstream)?;
            self.started = true;
            output.extend(event("message_start", &json!({"type":"message_start","message":{"id":format!("msg_{}",uuid::Uuid::new_v4().simple()),"type":"message","role":"assistant","model":model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":0,"output_tokens":0}}})));
        }
        self.usage = observation;
        let Some(choice) = value["choices"].get(0) else {
            return Ok(output);
        };
        if let Some(reason) = choice["finish_reason"].as_str() {
            self.reason = Some(stop_reason(reason)?.to_owned());
        }
        if let Some(sequence) = choice["matched_stop"].as_str() {
            self.matched_stop = Some(sequence.to_owned());
            self.reason = Some("stop_sequence".to_owned());
        }
        let delta = &choice["delta"];
        if let Some(text) = delta["content"].as_str().filter(|s| !s.is_empty()) {
            let index = if let Some(index) = self.text_index {
                index
            } else {
                let index = self.next_index;
                self.next_index += 1;
                self.text_index = Some(index);
                output.extend(event("content_block_start", &json!({"type":"content_block_start","index":index,"content_block":{"type":"text","text":""}})));
                index
            };
            output.extend(event("content_block_delta", &json!({"type":"content_block_delta","index":index,"delta":{"type":"text_delta","text":text}})));
        }
        if let Some(calls) = delta["tool_calls"].as_array() {
            for call in calls {
                let key = call["index"].as_u64().ok_or_else(invalid_upstream)?;
                if !self.tools.contains_key(&key) && self.tools.len() >= 1024 {
                    return Err(invalid_upstream());
                }
                let tool = self.tools.entry(key).or_default();
                if let Some(id) = call["id"].as_str() {
                    tool.id.push_str(id);
                }
                if let Some(name) = call["function"]["name"].as_str() {
                    tool.name.push_str(name);
                }
                if tool.id.len() > 1024 || tool.name.len() > 1024 {
                    return Err(invalid_upstream());
                }
                if let Some(arguments) = call["function"]["arguments"].as_str() {
                    let index = if let Some(index) = tool.index {
                        index
                    } else {
                        if tool.id.is_empty() || tool.name.is_empty() {
                            return Err(invalid_upstream());
                        }
                        let index = self.next_index;
                        self.next_index += 1;
                        tool.index = Some(index);
                        output.extend(event("content_block_start", &json!({"type":"content_block_start","index":index,"content_block":{"type":"tool_use","id":tool.id,"name":tool.name,"input":{}}})));
                        index
                    };
                    if !arguments.is_empty() {
                        output.extend(event("content_block_delta", &json!({"type":"content_block_delta","index":index,"delta":{"type":"input_json_delta","partial_json":arguments}})));
                    }
                }
            }
        }
        Ok(output)
    }

    fn finish(&mut self) -> io::Result<Vec<u8>> {
        let reason = self.reason.as_ref().ok_or_else(invalid_upstream)?;
        if !self.started {
            return Err(invalid_upstream());
        }
        let mut output = Vec::new();
        for tool in self.tools.values_mut().filter(|tool| tool.index.is_none()) {
            if tool.id.is_empty() || tool.name.is_empty() {
                return Err(invalid_upstream());
            }
            let index = self.next_index;
            self.next_index += 1;
            tool.index = Some(index);
            output.extend(event("content_block_start", &json!({"type":"content_block_start","index":index,"content_block":{"type":"tool_use","id":tool.id,"name":tool.name,"input":{}}})));
        }
        for index in 0..self.next_index {
            output.extend(event(
                "content_block_stop",
                &json!({"type":"content_block_stop","index":index}),
            ));
        }
        output.extend(event("message_delta", &json!({"type":"message_delta","delta":{"stop_reason":reason,"stop_sequence":self.matched_stop},"usage":usage(self.usage)})));
        output.extend(event("message_stop", &json!({"type":"message_stop"})));
        self.done = true;
        Ok(output)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model_response::ModelResponse;

    fn decoder() -> ModelResponse<MessagesOutput> {
        ModelResponse::new("public".into(), true).with_output(MessagesOutput::new(true))
    }

    fn frame(value: &Value) -> Vec<u8> {
        format!("data: {value}\r\n\r\n").into_bytes()
    }

    #[test]
    fn stop_matches_and_length_are_translated() {
        for (reason, matched, expected) in [
            ("stop", json!("END"), "stop_sequence"),
            ("length", Value::Null, "max_tokens"),
            ("stop", Value::Null, "end_turn"),
        ] {
            let value = json!({"model":"public","choices":[{"message":{"content":"hello"},"finish_reason":reason,"matched_stop":matched}],"usage":{"prompt_tokens":10,"completion_tokens":2}});
            let output = message(&value, Observation::default()).unwrap();
            assert_eq!(output["stop_reason"], expected);
            assert_eq!(output["stop_sequence"], matched);
        }
    }

    #[test]
    fn split_utf8_parallel_tools_and_empty_arguments_survive() {
        let frames = [
            json!({"model":"public","choices":[{"delta":{"content":"日"}}]}),
            json!({"model":"public","choices":[{"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"second"}},{"index":0,"id":"a","function":{"name":"first","arguments":""}}]}}]}),
            json!({"model":"public","choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}),
            json!({"model":"public","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":5}}),
        ];
        let mut input = frames.iter().flat_map(frame).collect::<Vec<_>>();
        input.extend(b"data: [DONE]\r\n\r\n");
        let mut stream = decoder();
        let mut output = Vec::new();
        for b in input {
            output.extend(stream.push(&[b]).unwrap());
        }
        assert!(stream.stream_done());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("日"));
        assert!(text.contains("\"name\":\"second\""));
        assert!(text.contains("\"name\":\"first\""));
        assert_eq!(text.matches("event: content_block_stop").count(), 3);
        assert_eq!(text.matches("event: message_stop").count(), 1);
        assert!(text.contains("\"output_tokens\":5"));
    }

    #[test]
    fn incomplete_and_invalid_streams_do_not_complete() {
        let mut stream = decoder();
        stream
            .push(&frame(
                &json!({"model":"public","choices":[{"delta":{"content":"hello"}}]}),
            ))
            .unwrap();
        assert!(!stream.stream_done());
        assert!(stream.push(b"data: [DONE]\n\n").is_err());
        assert!(!stream.stream_done());
        let mut stream = decoder();
        assert!(stream.push(b"data: invalid\n\n").is_err());
        assert!(decoder().push(&vec![b'x'; 16 * 1024 * 1024 + 1]).is_err());
    }

    #[test]
    fn tool_metadata_is_bounded_and_unknown_blocks_are_refused() {
        let mut stream = decoder();
        assert!(stream.push(&frame(&json!({"model":"public","choices":[{"delta":{"tool_calls":[{"index":0,"id":"x".repeat(1025),"function":{"name":"first","arguments":""}}]}}]}))).is_err());
        assert_eq!(request(&json!({"model":"public","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"data":"private"}}]}]})).unwrap_err(),"unsupported_messages_content");
    }
}
