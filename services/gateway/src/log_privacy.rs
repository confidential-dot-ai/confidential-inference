//! Rules that keep request content and personal data out of gateway logs.
//!
//! The gateway writes its log events to the container stdout, one JSON object
//! per line ([`stdout_layer`]). The node log agent reads them from the node,
//! and it and the telemetry collector keep only reviewed records before logs
//! leave the cluster (`docs/telemetry-egress.md`). So a log event must never
//! carry a request or response body, a header, a client address, or a raw
//! key record ID:
//!
//! - Log messages are fixed text, or the audit record of
//!   `crate::TracingAuditSink`. Values go in fields, and the node log agent
//!   drops every field. Fields still never carry request or response text,
//!   headers, client addresses, or raw key record IDs.
//! - [`log_filter`] holds the HTTP libraries at `warn`, whatever `RUST_LOG`
//!   says. At `debug` and `trace` they can print headers, frames, and
//!   rejection texts that quote the request.
//! - [`install_panic_hook`] replaces the default hook, which prints the
//!   panic message. A message can contain a value from a request.
//! - [`KeyPseudonyms`] replaces a key record ID with a keyed hash before the
//!   ID goes into a log record.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::{Layer, fmt::MakeWriter, registry::LookupSpan};

type HmacSha256 = Hmac<Sha256>;

/// The derivation label of the log pseudonym key. A new label gives new,
/// unlinkable pseudonyms.
const PSEUDONYM_CONTEXT: &[u8] = b"confidential.ai/gateway-log-key-pseudonym/v1";
/// Bytes of the HMAC kept in a pseudonym: 96 bits, so two keys of one
/// deployment do not collide in practice.
const PSEUDONYM_BYTES: usize = 12;

/// Targets that can log message content at `debug` or `trace`.
const HTTP_TARGETS: &[&str] = &[
    "hyper",
    "hyper_util",
    "h2",
    "reqwest",
    "tower",
    "tower_http",
    "axum",
    "axum_server",
    "rustls",
];

/// Keyed pseudonyms for key record IDs in log records.
///
/// The key is derived from the gateway's CDS secret, which only attested
/// gateway pods hold. Only a holder of the secret can map a pseudonym back to
/// a key record, by computing the pseudonym of each record. A log reader
/// without the secret cannot.
#[derive(Clone)]
pub struct KeyPseudonyms {
    key: [u8; 32],
}

impl KeyPseudonyms {
    /// Derive the pseudonym key from the gateway's CDS secret.
    #[must_use]
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut mac = HmacSha256::new_from_slice(secret)
            .unwrap_or_else(|_| unreachable!("HMAC accepts a key of any length"));
        mac.update(PSEUDONYM_CONTEXT);
        Self {
            key: mac.finalize().into_bytes().into(),
        }
    }

    /// The pseudonym of one key record ID: `kp_` and 24 hexadecimal digits.
    #[must_use]
    pub fn pseudonym(&self, key_id: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC accepts a key of any length"));
        mac.update(key_id.as_bytes());
        let digest = mac.finalize().into_bytes();
        format!("kp_{}", hex::encode(&digest[..PSEUDONYM_BYTES]))
    }
}

/// Whether an event may reach any log output. Events of the HTTP libraries
/// pass only at `warn` and `error`. Every other event passes, and the
/// `RUST_LOG` filter decides.
#[must_use]
pub fn allowed(metadata: &Metadata<'_>) -> bool {
    !is_http_target(metadata.target()) || *metadata.level() <= Level::WARN
}

fn is_http_target(target: &str) -> bool {
    HTTP_TARGETS.iter().any(|prefix| {
        target
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
    })
}

/// The filter of every log output of the gateway. See [`allowed`].
#[must_use]
pub fn log_filter() -> tracing_subscriber::filter::FilterFn<fn(&Metadata<'_>) -> bool> {
    tracing_subscriber::filter::filter_fn(allowed as fn(&Metadata<'_>) -> bool)
}

/// The log output of the gateway: one JSON object per line, written to
/// `writer`, behind [`log_filter`]. A line has the form
/// `{"timestamp":"...","level":"INFO","message":"<fixed text>",<fields>}`,
/// with no span, target, or terminal colour codes. The gateway passes
/// `std::io::stdout`; the tests pass a capture buffer.
pub fn stdout_layer<S, W>(writer: W) -> impl Layer<S> + Send + Sync + 'static
where
    S: Subscriber + for<'span> LookupSpan<'span>,
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_ansi(false)
        .with_writer(writer)
        .with_filter(log_filter())
}

/// Replace the default panic hook. The new hook logs a fixed message and the
/// source location. It never prints the panic message, because a message can
/// contain a value from a request.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_default();
        tracing::error!(
            location,
            "the gateway panicked; the panic message is not logged"
        );
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonyms_are_stable_keyed_and_opaque() {
        let secret = [7_u8; 32];
        let first = KeyPseudonyms::from_secret(&secret);
        let again = KeyPseudonyms::from_secret(&secret);
        let other = KeyPseudonyms::from_secret(&[8_u8; 32]);
        let value = first.pseudonym("key_fa83e9fdbfaf435abe769ba83d2ffe5e");
        assert_eq!(
            value,
            again.pseudonym("key_fa83e9fdbfaf435abe769ba83d2ffe5e")
        );
        assert_ne!(
            value,
            other.pseudonym("key_fa83e9fdbfaf435abe769ba83d2ffe5e")
        );
        assert_ne!(value, first.pseudonym("key_other"));
        assert!(!value.contains("fa83e9"));
        assert_eq!(value.len(), 3 + 2 * PSEUDONYM_BYTES);
        assert!(value.starts_with("kp_"));
    }

    #[test]
    fn http_targets_are_matched_by_crate() {
        for target in [
            "hyper",
            "hyper::proto::h1",
            "h2::codec",
            "axum::rejection",
            "reqwest::connect",
        ] {
            assert!(is_http_target(target), "{target}");
        }
        for target in [
            "confidential_gateway",
            "hyperloglog",
            "h2o",
            "axum_extra_like",
        ] {
            assert!(!is_http_target(target), "{target}");
        }
    }
}
