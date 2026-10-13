//! Gateway settings that apply to new requests. Trust inputs remain fixed.

use serde::{Deserialize, Serialize};

use crate::runtime_config::Versioned;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySettings {
    pub schema_version: u32,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router_service: Option<String>,
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

impl Versioned for GatewaySettings {
    fn revision(&self) -> u64 {
        self.revision
    }
}

impl GatewaySettings {
    /// Validate the complete snapshot before accepting it.
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
            || self.revision == 0
            || !names_valid(&self.catalog_model_ids)
            || !names_valid(&self.inference_model_ids)
            || !self
                .catalog_model_ids
                .iter()
                .all(|name| self.inference_model_ids.contains(name))
            || !(1024..=8 * 1024 * 1024).contains(&self.maximum_body_bytes)
            || !(1..=3600).contains(&self.upstream_timeout_seconds)
            || !(1..=120).contains(&self.body_timeout_seconds)
            || !(1..=600).contains(&self.stream_idle_timeout_seconds)
            || self.stream_idle_timeout_seconds > self.upstream_timeout_seconds
            || !(1..=30).contains(&self.attestation_cache_seconds)
            || [
                self.global_request_concurrency,
                self.per_address_concurrency,
                self.inference_concurrency,
                self.per_key_concurrency,
                self.attestation_concurrency,
            ]
            .iter()
            .any(|value| !(1..=4096).contains(value))
            || self.inference_queue > 4096
            || !(1..=30).contains(&self.queue_timeout_seconds)
            || !(1..=10_000).contains(&self.requests_per_address_per_second)
            || self.router_service.as_ref().is_some_and(|name| {
                !(name == "sglang-router" || name.starts_with("router-"))
                    || name.len() > 63
                    || name.ends_with('-')
                    || !name.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err("invalid gateway runtime settings".into());
        }
        Ok(())
    }
}
