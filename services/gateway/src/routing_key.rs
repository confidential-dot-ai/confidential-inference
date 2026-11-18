//! The routing key the gateway sends the sglang-router with each inference
//! request.
//!
//! In prefill/decode mode the router's `manual` policy keeps every
//! `X-SMG-Routing-Key` value on one worker, so a conversation's next turn
//! reuses the prefix cache of the worker that served its last turn. A request
//! without the header goes to a random worker.
//!
//! The gateway never forwards a caller's header value. It sends an HMAC, under
//! a secret derived from the API key pepper, of the caller's API key ID and
//! one of:
//!
//! - the caller's own `X-SMG-Routing-Key`, when it is 1 to 128 visible ASCII
//!   bytes;
//! - otherwise, for `/v1/chat/completions`, the model and the messages up to
//!   and including the first user message, which every later turn of the
//!   conversation repeats unchanged;
//! - otherwise, for `/v1/responses`, the model, the `instructions`, and the
//!   `input` items up to and including the first user message. The gateway
//!   accepts only stateless Responses requests, so each turn sends the full
//!   input again. A string `input` counts as one user message.
//!
//! `/v1/completions` gets a key only from the caller's header: its prompt
//! grows with each turn, and no fixed part of it identifies a conversation.
//! The router therefore never sees a client string or prompt text, and one API
//! key can neither share nor target another key's routing slot.
//!
//! Every gateway of a deployment reads the same pepper, so every gateway
//! derives the same key for a conversation, across restarts and replicas. A
//! router with a key-hashing policy (`consistent_hashing`) then sends the
//! conversation to one worker whichever gateway it entered through. Rotating
//! the pepper re-keys every conversation once.

use axum::http::{HeaderName, HeaderValue};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;

/// The header the router's `manual` and `consistent_hashing` policies read.
pub static HEADER: HeaderName = HeaderName::from_static("x-smg-routing-key");

const CONTEXT: &[u8] = b"confidential.ai/gateway-routing-key/v1";
// Separates the routing secret from every other use of the pepper.
const SECRET_CONTEXT: &[u8] = b"confidential.ai/gateway-routing-secret/v1";
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

    /// Derive the secret from the API key pepper, so that every gateway with
    /// the same pepper derives the same routing keys.
    #[must_use]
    pub fn from_pepper(pepper: &[u8]) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(pepper)
            .unwrap_or_else(|_| unreachable!("HMAC accepts a key of any length"));
        mac.update(SECRET_CONTEXT);
        Self {
            secret: mac.finalize().into_bytes().into(),
        }
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
        match route {
            "/v1/chat/completions" => {
                self.sign_opening(key_id, b"chat", &conversation_opening(payload)?)
            }
            "/v1/responses" => {
                self.sign_opening(key_id, b"responses", &responses_opening(payload)?)
            }
            _ => None,
        }
    }

    /// Sign the JSON of an opening without a copy of it: the opening of a
    /// 1M-token request can be most of its body. The JSON is written twice,
    /// first to count its length, which the MAC takes before the bytes.
    fn sign_opening(
        &self,
        key_id: &str,
        kind: &[u8],
        opening: &impl Serialize,
    ) -> Option<HeaderValue> {
        let mut counter = Counter(0);
        serde_json::to_writer(&mut counter, opening).ok()?;
        let mut mac = self.mac(key_id, kind);
        mac.update(&counter.0.to_be_bytes());
        serde_json::to_writer(MacWriter(&mut mac), opening).ok()?;
        Some(Self::key(mac))
    }

    fn sign(&self, key_id: &str, kind: &[u8], material: &[u8]) -> HeaderValue {
        let mut mac = self.mac(key_id, kind);
        mac.update(&(material.len() as u64).to_be_bytes());
        mac.update(material);
        Self::key(mac)
    }

    // Each field carries its length, so no two inputs share an encoding.
    fn mac(&self, key_id: &str, kind: &[u8]) -> Hmac<Sha256> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts a key of any length"));
        for field in [CONTEXT, key_id.as_bytes(), kind] {
            mac.update(&(field.len() as u64).to_be_bytes());
            mac.update(field);
        }
        mac
    }

    fn key(mac: Hmac<Sha256>) -> HeaderValue {
        let digest = mac.finalize().into_bytes();
        HeaderValue::from_str(&hex::encode(&digest[..KEY_BYTES]))
            .unwrap_or_else(|_| unreachable!("hex is a valid header value"))
    }
}

/// Counts the bytes written to it.
struct Counter(u64);

impl std::io::Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Feeds the bytes written to it into a MAC.
struct MacWriter<'a>(&'a mut Hmac<Sha256>);

impl std::io::Write for MacWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

static NULL: Value = Value::Null;

/// One message of an opening. The fields are in key order, so the JSON is
/// the JSON `serde_json` writes for a `Value` with these keys.
#[derive(Serialize)]
struct Turn<'a> {
    content: Content<'a>,
    role: &'a str,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Content<'a> {
    Value(&'a Value),
    Text(&'a str),
}

#[derive(Serialize)]
struct ChatOpening<'a> {
    messages: Vec<Turn<'a>>,
    model: &'a str,
}

#[derive(Serialize)]
struct ResponsesOpening<'a> {
    input: Vec<Turn<'a>>,
    instructions: &'a Value,
    model: &'a str,
}

fn valid_client_key(value: &HeaderValue) -> bool {
    let bytes = value.as_bytes();
    (1..=MAXIMUM_CLIENT_KEY_BYTES).contains(&bytes.len()) && bytes.iter().all(u8::is_ascii_graphic)
}

/// The model and each message's role and content, up to and including the
/// first user message. The fields are in key order, like the keys of a
/// `serde_json` object, so the encoding does not depend on the order of the
/// caller's keys. It borrows the content: it copies no prompt text.
fn conversation_opening(payload: &Value) -> Option<ChatOpening<'_>> {
    let model = payload.get("model")?.as_str()?;
    let mut opening = Vec::new();
    for message in payload.get("messages")?.as_array()? {
        let role = message.get("role")?.as_str()?;
        let content = Content::Value(message.get("content").unwrap_or(&NULL));
        opening.push(Turn { content, role });
        if role == "user" {
            return Some(ChatOpening {
                messages: opening,
                model,
            });
        }
    }
    None
}

/// The model, the instructions, and each input item's role and content, up
/// to and including the first user message of a Responses API request.
fn responses_opening(payload: &Value) -> Option<ResponsesOpening<'_>> {
    let model = payload.get("model")?.as_str()?;
    let instructions = payload.get("instructions").unwrap_or(&NULL);
    let first_user = |input| {
        Some(ResponsesOpening {
            input,
            instructions,
            model,
        })
    };
    let input = payload.get("input")?;
    if let Some(text) = input.as_str() {
        return first_user(vec![Turn {
            content: Content::Text(text),
            role: "user",
        }]);
    }
    let mut opening = Vec::new();
    for item in input.as_array()? {
        let role = item.get("role")?.as_str()?;
        let content = Content::Value(item.get("content").unwrap_or(&NULL));
        opening.push(Turn { content, role });
        if role == "user" {
            return first_user(opening);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// The borrowed openings sign the same JSON as a `Value` of the same
    /// keys, so the encoding still sorts the keys.
    #[test]
    fn the_borrowed_opening_signs_the_sorted_json() {
        let keys = keys();
        let sign = |kind: &[u8], value: &Value| {
            Some(keys.sign("key", kind, &serde_json::to_vec(value).unwrap_or_default()))
        };
        let chat = json!({"model": "m", "messages": [
            {"content": "s", "role": "system", "name": "x"},
            {"role": "user", "content": [{"type": "text", "text": "hello"}]},
            {"role": "assistant", "content": "later"},
        ]});
        let expected = json!({"model": "m", "messages": [
            {"role": "system", "content": "s"},
            {"role": "user", "content": [{"type": "text", "text": "hello"}]},
        ]});
        assert_eq!(
            keys.derive("key", CHAT, None, &chat),
            sign(b"chat", &expected)
        );
        let responses = json!({"model": "m", "input": [{"role": "user"}]});
        let expected = json!({"model": "m", "instructions": null, "input": [
            {"role": "user", "content": null},
        ]});
        assert_eq!(
            keys.derive("key", "/v1/responses", None, &responses),
            sign(b"responses", &expected)
        );
        let text = json!({"model": "m", "instructions": "i", "input": "hi"});
        let expected = json!({"model": "m", "instructions": "i", "input": [
            {"role": "user", "content": "hi"},
        ]});
        assert_eq!(
            keys.derive("key", "/v1/responses", None, &text),
            sign(b"responses", &expected)
        );
    }

    const CHAT: &str = "/v1/chat/completions";

    #[test]
    fn gateways_with_one_pepper_derive_the_same_keys() {
        let payload = turn(&json!([{"role": "user", "content": "hello"}]));
        let one = RoutingKeys::from_pepper(&[3; 32]).derive("key_record_1", CHAT, None, &payload);
        let two = RoutingKeys::from_pepper(&[3; 32]).derive("key_record_1", CHAT, None, &payload);
        let other = RoutingKeys::from_pepper(&[4; 32]).derive("key_record_1", CHAT, None, &payload);
        assert!(one.is_some());
        assert_eq!(one, two);
        assert_ne!(one, other);
        // The secret is not the pepper itself.
        assert_ne!(
            one,
            RoutingKeys::with_secret([3; 32]).derive("key_record_1", CHAT, None, &payload)
        );
    }

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

    #[test]
    fn every_turn_of_a_responses_conversation_gets_one_key() {
        const RESPONSES: &str = "/v1/responses";
        let first =
            json!({"model": "deepseek", "instructions": "Be terse.", "input": "Name a prime."});
        let second = json!({"model": "deepseek", "instructions": "Be terse.", "input": [
            {"role": "user", "content": "Name a prime."},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "7"}]},
            {"role": "user", "content": "Another."}
        ]});
        let key = derive(None, RESPONSES, &first);
        assert!(key.is_some());
        assert_eq!(key, derive(None, RESPONSES, &second));
        let other =
            json!({"model": "deepseek", "instructions": "Be verbose.", "input": "Name a prime."});
        assert_ne!(key, derive(None, RESPONSES, &other));
        // The kind keeps a Responses key apart from a chat key.
        let chat = turn(&json!([{"role": "user", "content": "Name a prime."}]));
        assert_ne!(key, derive(None, CHAT, &chat));
        for payload in [
            json!({"model": "deepseek"}),
            json!({"model": "deepseek", "input": []}),
            json!({"model": "deepseek", "input": [{"type": "function_call_output", "output": "x"}]}),
            json!({"input": "no model"}),
        ] {
            assert_eq!(derive(None, RESPONSES, &payload), None, "{payload}");
        }
    }
}
