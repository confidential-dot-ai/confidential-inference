//! API selection and request policy. Transport and admission stay shared.
use crate::{
    messages,
    model_response::{OpenAiOutput, Output, Wire},
    settings::UnsupportedParameter,
};
use axum::{
    Json,
    body::Body,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};
use std::io;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Api {
    Completions,
    ChatCompletions,
    Responses,
    Messages,
}

/// A fixed code for a later API-specific error renderer. Never upstream text.
#[derive(Clone, Copy)]
pub(crate) struct ErrorCode(pub(crate) &'static str);

pub(crate) fn tag_error(mut response: Response<Body>, code: &'static str) -> Response<Body> {
    response.extensions_mut().insert(ErrorCode(code));
    response
}

pub(crate) enum RequestError {
    Messages(&'static str),
    StatefulResponses(&'static str),
}

impl RequestError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::StatefulResponses(_) => "stateful_responses_request",
            Self::Messages(code) => code,
        }
    }
    pub(crate) fn response(self) -> Response<Body> {
        match self {
            Self::StatefulResponses(field) => stateful_responses_request(field),
            Self::Messages(code) => crate::client_error(StatusCode::BAD_REQUEST, code),
        }
    }
}

impl Api {
    pub(crate) fn route(self) -> &'static str {
        match self {
            Self::Completions => "/v1/completions",
            Self::ChatCompletions => "/v1/chat/completions",
            Self::Responses => "/v1/responses",
            Self::Messages => "/v1/messages",
        }
    }
    pub(crate) fn upstream_route(self) -> &'static str {
        match self {
            Self::Messages => Self::ChatCompletions.route(),
            _ => self.route(),
        }
    }
    pub(crate) fn wire(self) -> Wire {
        match self {
            Self::Responses => Wire::Responses,
            _ => Wire::Completions,
        }
    }

    pub(crate) fn output(self, streaming: bool) -> ClientOutput {
        match self {
            Self::Messages => ClientOutput::Messages(messages::MessagesOutput::new(streaming)),
            _ => ClientOutput::OpenAi(OpenAiOutput),
        }
    }

    /// Return whether a stated policy changed the body.
    pub(crate) fn prepare(self, payload: &mut Value) -> Result<bool, RequestError> {
        if self == Self::Messages {
            *payload = messages::request(payload).map_err(RequestError::Messages)?;
            Ok(true)
        } else if self == Self::Responses {
            stateless_responses_request(payload).map_err(RequestError::StatefulResponses)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn stream_usage(self, payload: &Value, recording: bool) -> bool {
        self.wire() == Wire::Completions
            && (recording || self == Self::Messages)
            && payload["stream"] == true
    }
    pub(crate) fn hide_usage(self, payload: &Value, added: bool) -> bool {
        self != Self::Messages
            && self.wire() == Wire::Completions
            && added
            && payload["stream_options"]["include_usage"] != true
    }
}

/// Refuse each Responses API request field that needs server-side state, and
/// tell the upstream not to store the response.
///
/// No component of this service may keep a conversation: a stored response
/// would hold prompt and output text after the request ends, and a later
/// request could reach a different worker. The caller sends the full input
/// with each request instead. A `null` value counts as absent.
///
/// Returns the refused field. A body that is not a JSON object passes
/// unchanged; the upstream rejects it.
fn stateless_responses_request(payload: &mut Value) -> Result<(), &'static str> {
    let Some(object) = payload.as_object_mut() else {
        return Ok(());
    };
    for field in ["previous_response_id", "conversation"] {
        if object.get(field).is_some_and(|value| !value.is_null()) {
            return Err(field);
        }
    }
    for field in ["store", "background"] {
        match object.get(field) {
            None | Some(Value::Null | Value::Bool(false)) => {}
            Some(_) => return Err(field),
        }
    }
    // OpenAI and SGLang both default `store` to true.
    object.insert("store".to_owned(), Value::Bool(false));
    // The router's typed request turns an absent `stream` into `null`.
    if object.get("stream").is_none_or(Value::is_null) {
        object.insert("stream".to_owned(), Value::Bool(false));
    }
    Ok(())
}

fn stateful_responses_request(field: &'static str) -> Response<Body> {
    let or_false = if matches!(field, "store" | "background") {
        " or set it to false"
    } else {
        ""
    };
    let message = format!(
        "The gateway keeps no response state. Remove `{field}`{or_false}, and send the full input with each request."
    );
    tag_error(
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":{
                "code":"stateful_responses_not_supported",
                "message":message,
            }})),
        )
            .into_response(),
        "stateful_responses_not_supported",
    )
}

/// The Responses API asks for output logprobs with this `include` item.
const RESPONSES_LOGPROBS: &str = "message.output_text.logprobs";

/// The first configured parameter that the upstream body sets to a refused
/// value: anything but absent, `null`, or one of its `allowed` values. A body
/// that is not a JSON object passes; the upstream rejects it.
///
/// The Responses API has no `logprobs` field: an `include` of
/// `message.output_text.logprobs` asks for them, so it counts as
/// `logprobs: true`.
pub(crate) fn unsupported_parameter<'a>(
    api: Api,
    payload: &Value,
    parameters: &'a [UnsupportedParameter],
) -> Option<&'a str> {
    let object = payload.as_object()?;
    let responses_logprobs = Value::Bool(true);
    parameters.iter().find_map(|parameter| {
        let value = match object.get(&parameter.name) {
            None if api == Api::Responses
                && parameter.name == "logprobs"
                && object
                    .get("include")
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.iter().any(|item| item == RESPONSES_LOGPROBS)) =>
            {
                &responses_logprobs
            }
            None | Some(Value::Null) => return None,
            Some(value) => value,
        };
        let allowed = parameter
            .allowed
            .iter()
            .any(|candidate| match (candidate, value) {
                (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
                _ => candidate == value,
            });
        (!allowed).then_some(parameter.name.as_str())
    })
}

/// 400 `unsupported_parameter`. It names the parameter from the gateway
/// settings and never quotes the request's value.
pub(crate) fn unsupported_parameter_response(name: &str) -> Response<Body> {
    tag_error(
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":{
                "code":"unsupported_parameter",
                "message":format!("The model does not support the request parameter `{name}` with this value. Remove it."),
            }})),
        )
            .into_response(),
        "unsupported_parameter",
    )
}

/// The selected writer owns only the state needed by that client format.
pub(crate) enum ClientOutput {
    OpenAi(OpenAiOutput),
    Messages(messages::MessagesOutput),
}

impl Output for ClientOutput {
    fn value(
        &mut self,
        value: Value,
        usage: crate::usage::Observation,
        streaming: bool,
        ending: &[u8],
    ) -> io::Result<Vec<u8>> {
        match self {
            Self::OpenAi(output) => output.value(value, usage, streaming, ending),
            Self::Messages(output) => output.value(value, usage, streaming, ending),
        }
    }
    fn raw(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::OpenAi(output) => output.raw(bytes),
            Self::Messages(output) => output.raw(bytes),
        }
    }
    fn done(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::OpenAi(output) => output.done(bytes),
            Self::Messages(output) => output.done(bytes),
        }
    }
    fn finish(&mut self) -> io::Result<Vec<u8>> {
        match self {
            Self::OpenAi(output) => output.finish(),
            Self::Messages(output) => output.finish(),
        }
    }
    fn failure(&mut self, error: io::Error) -> io::Result<Vec<u8>> {
        match self {
            Self::OpenAi(output) => output.failure(error),
            Self::Messages(output) => output.failure(error),
        }
    }
}
