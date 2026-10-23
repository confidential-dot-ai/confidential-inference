//! Gateway settings from the chart's settings `ConfigMap`. The gateway reads
//! them once at start; the chart rolls the pods when they change.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySettings {
    pub schema_version: u32,
    #[serde(default)]
    pub router_service: Option<String>,
    // The chart still renders `evidence`, `attestationCacheSeconds` and
    // `attestationConcurrency`; the gateway reads none of them.
    #[serde(default)]
    pub evidence: Option<serde_json::Value>,
    pub catalog_model_ids: Vec<String>,
    pub inference_model_ids: Vec<String>,
    pub maximum_body_bytes: usize,
    pub upstream_timeout_seconds: u64,
    pub body_timeout_seconds: u64,
    pub stream_idle_timeout_seconds: u64,
    pub attestation_cache_seconds: u64,
    pub global_request_concurrency: usize,
    pub per_address_concurrency: usize,
    pub inference_concurrency: usize,
    pub inference_queue: usize,
    pub queue_timeout_seconds: u64,
    pub per_key_concurrency: usize,
    pub attestation_concurrency: usize,
    pub requests_per_address_per_second: u32,
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
        Ok(())
    }
}
