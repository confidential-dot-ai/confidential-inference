//! The routing key the gateway sends the sglang-router with each inference
//! request.
//!
//! In prefill/decode mode the router's `manual` policy keeps every
//! `X-SMG-Routing-Key` value on one worker, so a conversation's next turn
//! reuses the prefix cache of the worker that served its last turn. A request
//! without the header goes to a random worker.
//!
//! The gateway never forwards a caller's header value. It sends an HMAC, under
//! a secret drawn at process start, of the caller's API key ID and one of:
//!
//! - the caller's own `X-SMG-Routing-Key`, when it is 1 to 128 visible ASCII
//!   bytes;
//! - otherwise, for `/v1/chat/completions`, the model and the messages up to
//!   and including the first user message, which every later turn of the
//!   conversation repeats unchanged.
//!
//! `/v1/completions` gets a key only from the caller's header: its prompt
//! grows with each turn, and no fixed part of it identifies a conversation.
//! The router therefore never sees a client string or prompt text, and one API
//! key can neither share nor target another key's routing slot. A gateway
//! restart draws a new secret, so each conversation is assigned a worker
//! again; replicas would each assign their own.

use axum::http::{HeaderName, HeaderValue};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

/// The header the router's `manual` policy reads.
pub static HEADER: HeaderName = HeaderName::from_static("x-smg-routing-key");

const CONTEXT: &[u8] = b"confidential.ai/gateway-routing-key/v1";
/// The key is 16 bytes of the HMAC: 32 hex characters.
const KEY_BYTES: usize = 16;
const MAXIMUM_CLIENT_KEY_BYTES: usize = 128;

/// Derives routing keys under one secret.
pub struct RoutingKeys {
    secret: [u8; 32],
}

impl RoutingKeys {
    /// Draw a new secret from the operating system.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system has no randomness.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut secret = [0; 32];
        getrandom::fill(&mut secret)?;
        Ok(Self { secret })
    }

    #[cfg(test)]
    fn with_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    /// The routing key for one request, from the caller's `X-SMG-Routing-Key`
    /// or the request body, or `None` when nothing identifies its
    /// conversation.
    #[must_use]
    pub fn derive(
        &self,
        key_id: &str,
        route: &str,
        client_key: Option<&HeaderValue>,
        payload: &Value,
    ) -> Option<HeaderValue> {
        if let Some(value) = client_key.filter(|value| valid_client_key(value)) {
            return Some(self.sign(key_id, b"client", value.as_bytes()));
        }
        if route != "/v1/chat/completions" {
            return None;
        }
        let opening = conversation_opening(payload)?;
        let material = serde_json::to_vec(&opening).ok()?;
        Some(self.sign(key_id, b"chat", &material))
    }

    fn sign(&self, key_id: &str, kind: &[u8], material: &[u8]) -> HeaderValue {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts a key of any length"));
        // Each field carries its length, so no two inputs share an encoding.
        for field in [CONTEXT, key_id.as_bytes(), kind, material] {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        let digest = mac.finalize().into_bytes();
        HeaderValue::from_str(&hex::encode(&digest[..KEY_BYTES]))
            .unwrap_or_else(|_| unreachable!("hex is a valid header value"))
    }
}

fn valid_client_key(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    (1..=MAXIMUM_CLIENT_KEY_BYTES).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic)
}

/// The model and each message's role and content, up to and including the
/// first user message. `serde_json` sorts object keys, so the encoding does not
/// depend on the order of the caller's keys.
fn conversation_opening(payload: &Value) -> Option<Value> {
    let model = payload.get("model")?.as_str()?;
    let mut opening = Vec::new();
    for message in payload.get("messages")?.as_array()? {
        let role = message.get("role")?.as_str()?;
        let content = message.get("content").cloned().unwrap_or(Value::Null);
        opening.push(json!({"role": role, "content": content}));
        if role == "user" {
            return Some(json!({"model": model, "messages": opening}));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHAT: &str = "/v1/chat/completions";

    fn keys() -> RoutingKeys {
        RoutingKeys::with_secret([7; 32])
    }

    fn turn(messages: &Value) -> Value {
        json!({"model": "deepseek", "messages": messages})
    }

    fn header(value: &[u8]) -> HeaderValue {
        HeaderValue::from_bytes(value).unwrap_or_else(|_| unreachable!())
    }

    fn derive(
        client_key: Option<&HeaderValue>,
        route: &str,
        payload: &Value,
    ) -> Option<HeaderValue> {
        keys().derive("key_record_1", route, client_key, payload)
    }

    #[test]
    fn every_turn_of_a_conversation_gets_one_key() {
        let first = turn(&json!([
            {"role": "system", "content": "You are terse."},
            {"role": "user", "content": "Name a prime."}
        ]));
        let second = turn(&json!([
            {"role": "system", "content": "You are terse."},
            {"role": "user", "content": "Name a prime."},
            {"role": "assistant", "content": "7"},
            {"role": "user", "content": "Another."}
        ]));
        let key = derive(None, CHAT, &first);
        assert!(key.is_some());
        assert_eq!(key, derive(None, CHAT, &second));
        let other = turn(&json!([
            {"role": "system", "content": "You are terse."},
            {"role": "user", "content": "Name a colour."}
        ]));
        assert_ne!(key, derive(None, CHAT, &other));
    }

    #[test]
    fn the_key_is_32_hex_characters_without_the_material() {
        let key = derive(Some(&header(b"conversation-42")), CHAT, &json!({}))
            .unwrap_or_else(|| unreachable!());
        let text = key.to_str().unwrap_or_else(|_| unreachable!());
        assert_eq!(text.len(), 32);
        assert!(text.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!(!text.contains("conversation"));
    }

    #[test]
    fn api_keys_never_share_a_key() {
        let payload = turn(&json!([{"role": "user", "content": "hello"}]));
        let client_key = header(b"conversation-42");
        for client_key in [Some(&client_key), None] {
            let first = keys().derive("key_record_1", CHAT, client_key, &payload);
            let second = keys().derive("key_record_2", CHAT, client_key, &payload);
            assert!(first.is_some());
            assert_ne!(first, second);
        }
    }

    #[test]
    fn secrets_never_share_a_key() {
        let payload = turn(&json!([{"role": "user", "content": "hello"}]));
        assert_ne!(
            keys().derive("key_record_1", CHAT, None, &payload),
            RoutingKeys::with_secret([8; 32]).derive("key_record_1", CHAT, None, &payload)
        );
    }

    #[test]
    fn a_valid_client_key_wins_over_the_messages() {
        let first = turn(&json!([{"role": "user", "content": "one"}]));
        let second = turn(&json!([{"role": "user", "content": "two"}]));
        let client_key = header(b"conversation-42");
        let client_key = Some(&client_key);
        assert_eq!(
            derive(client_key, CHAT, &first),
            derive(client_key, CHAT, &second)
        );
        assert_ne!(derive(client_key, CHAT, &first), derive(None, CHAT, &first));
        // Legacy completions get a key from the header alone.
        assert_eq!(
            derive(client_key, "/v1/completions", &json!({"prompt": "x"})),
            derive(client_key, CHAT, &first)
        );
    }

    #[test]
    fn an_invalid_client_key_falls_back_to_the_messages() {
        let payload = turn(&json!([{"role": "user", "content": "hello"}]));
        let derived = derive(None, CHAT, &payload);
        let too_long = vec![b'k'; MAXIMUM_CLIENT_KEY_BYTES + 1];
        for value in [
            b"".as_slice(),
            b"has space",
            b"tab\there",
            b"caf\xc3\xa9",
            &too_long,
        ] {
            assert_eq!(
                derive(Some(&header(value)), CHAT, &payload),
                derived,
                "{value:?}"
            );
        }
        let longest = header(&[b'k'; MAXIMUM_CLIENT_KEY_BYTES]);
        assert_ne!(derive(Some(&longest), CHAT, &payload), derived);
    }

    #[test]
    fn no_key_when_nothing_identifies_the_conversation() {
        let prompt = json!({"model": "deepseek", "prompt": "x"});
        assert_eq!(derive(None, "/v1/completions", &prompt), None);
        for payload in [
            json!({"model": "deepseek"}),
            json!({"model": "deepseek", "messages": []}),
            json!({"model": "deepseek", "messages": "hello"}),
            json!({"model": "deepseek", "messages": [{"role": "system", "content": "only"}]}),
            json!({"model": "deepseek", "messages": [{"content": "no role"}]}),
            json!({"messages": [{"role": "user", "content": "no model"}]}),
        ] {
            assert_eq!(derive(None, CHAT, &payload), None, "{payload}");
        }
    }

    #[test]
    fn the_key_ignores_the_order_of_the_callers_json_keys() {
        let first: Value = serde_json::from_str(
            r#"{"model":"deepseek","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"#,
        )
        .unwrap_or_else(|_| unreachable!());
        let second: Value = serde_json::from_str(
            r#"{"messages":[{"content":[{"text":"hi","type":"text"}],"role":"user"}],"model":"deepseek"}"#,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(derive(None, CHAT, &first), derive(None, CHAT, &second));
    }

    #[test]
    fn the_model_and_the_opening_change_the_key() {
        let base = turn(&json!([
            {"role": "system", "content": "a"},
            {"role": "user", "content": "b"}
        ]));
        let other_model = json!({"model": "other", "messages": base["messages"]});
        let other_system = turn(&json!([
            {"role": "system", "content": "A"},
            {"role": "user", "content": "b"}
        ]));
        let key = derive(None, CHAT, &base);
        assert_ne!(key, derive(None, CHAT, &other_model));
        assert_ne!(key, derive(None, CHAT, &other_system));
    }
}
