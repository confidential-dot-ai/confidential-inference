//! Gateway settings from the chart, in `GATEWAY_RUNTIME_CONFIG`. They are
//! environment, so the exact allowlist pins them and a change rolls the pods.

use serde::Deserialize;
use serde_json::Value;

/// A request parameter the served model does not support (the recipe's
/// `behavior.unsupportedParameters`). The gateway refuses a request that sets
/// it to any value but `null` or one of `allowed`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnsupportedParameter {
    pub name: String,
    /// The values that stay accepted, such as `1` for `n`. Numbers compare by
    /// value, so `1` also accepts `1.0`.
    #[serde(default)]
    pub allowed: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySettings {
    pub schema_version: u32,
    #[serde(default)]
    pub router_service: Option<String>,
    // The chart still renders `attestationCacheSeconds` and
    // `attestationConcurrency`; the gateway reads neither.
    pub catalog_model_ids: Vec<String>,
    pub inference_model_ids: Vec<String>,
    pub maximum_body_bytes: usize,
    pub upstream_timeout_seconds: u64,
    pub body_timeout_seconds: u64,
    pub stream_idle_timeout_seconds: u64,
    // Optional, so a settings file of an earlier chart still applies; the
    // process default stays then.
    #[serde(default)]
    pub first_token_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub body_memory_bytes: Option<usize>,
    pub attestation_cache_seconds: u64,
    pub global_request_concurrency: usize,
    pub per_address_concurrency: usize,
    pub inference_concurrency: usize,
    pub inference_queue: usize,
    pub queue_timeout_seconds: u64,
    pub per_key_concurrency: usize,
    pub attestation_concurrency: usize,
    pub requests_per_address_per_second: u32,
    // Optional: a chart without the field has none.
    #[serde(default)]
    pub unsupported_parameters: Vec<UnsupportedParameter>,
}

impl GatewaySettings {
    /// Validate the fields the process arguments cannot express. The startup
    /// argument checks bound the numeric limits.
    ///
    /// # Errors
    /// Returns an error for unsafe settings or inconsistent model lists.
    pub fn validate(&self) -> Result<(), String> {
        let names_valid = |names: &[String]| {
            names.len() <= 1024
                && names
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == names.len()
                && names.iter().all(|name| {
                    !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control)
                })
        };
        if self.schema_version != 1
            || !names_valid(&self.catalog_model_ids)
            || !names_valid(&self.inference_model_ids)
            || !self
                .catalog_model_ids
                .iter()
                .all(|name| self.inference_model_ids.contains(name))
            || self.stream_idle_timeout_seconds > self.upstream_timeout_seconds
            || self
                .first_token_timeout_seconds
                .is_some_and(|seconds| seconds > self.upstream_timeout_seconds)
            || self.router_service.as_ref().is_some_and(|name| {
                !(name == "sglang-router" || name.starts_with("router-"))
                    || name.len() > 63
                    || name.ends_with('-')
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err("invalid gateway settings".into());
        }
        let parameters = &self.unsupported_parameters;
        if parameters.len() > 64
            || parameters
                .iter()
                .map(|parameter| &parameter.name)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != parameters.len()
            || !parameters.iter().all(|parameter| {
                !parameter.name.is_empty()
                    && parameter.name.len() <= 64
                    && parameter.name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                    })
                    && parameter.allowed.len() <= 16
                    && parameter.allowed.iter().all(|value| {
                        matches!(value, Value::Bool(_) | Value::Number(_) | Value::String(_))
                    })
            })
        {
            return Err("invalid gateway settings: unsupportedParameters".into());
        }
        Ok(())
    }
}
