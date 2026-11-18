//! API selection and request policy. Transport and admission stay shared.
use crate::model_response::Wire;
use axum::{
    Json,
    body::Body,
    http::{Response, StatusCode},
    response::IntoResponse,
};
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Api {
    Completions,
    ChatCompletions,
    Responses,
}

impl Api {
    pub(crate) fn route(self) -> &'static str {
        match self {
            Self::Completions => "/v1/completions",
            Self::ChatCompletions => "/v1/chat/completions",
            Self::Responses => "/v1/responses",
        }
    }
    pub(crate) fn wire(self) -> Wire {
        match self {
            Self::Responses => Wire::Responses,
            _ => Wire::Completions,
        }
    }

    /// Return whether a stated policy changed the body.
    pub(crate) fn prepare(self, payload: &mut Value) -> Result<bool, &'static str> {
        if self == Self::Responses {
            stateless_responses_request(payload)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub(crate) fn stream_usage(self, payload: &Value, recording: bool) -> bool {
        self.wire() == Wire::Completions && recording && payload["stream"] == true
    }
    pub(crate) fn hide_usage(self, payload: &Value, added: bool) -> bool {
        self.wire() == Wire::Completions
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

pub(crate) fn request_error(field: &'static str) -> Response<Body> {
    let or_false = if matches!(field, "store" | "background") {
        " or set it to false"
    } else {
        ""
    };
    let message = format!(
        "The gateway keeps no response state. Remove `{field}`{or_false}, and send the full input with each request."
    );
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error":{
            "code":"stateful_responses_not_supported",
            "message":message,
        }})),
    )
        .into_response()
}
