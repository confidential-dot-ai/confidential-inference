//! Gateway settings from the chart's settings `ConfigMap`. The gateway reads
//! them once at start; the chart rolls the pods when they change.

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewaySettings {
    pub schema_version: u32,
    #[serde(default)]
    pub router_service: Option<String>,
    #[serde(default)]
    pub evidence: Option<EvidenceSettings>,
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

/// Public TLS origin and optional connection address.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceSettings {
    pub base_url: String,
    #[serde(default)]
    pub connect_host: Option<String>,
}

impl EvidenceSettings {
    /// Validate addresses without changing TLS trust or doing network I/O.
    ///
    /// # Errors
    /// Return an error for an unsafe origin or invalid connection host.
    pub fn validate(&self) -> Result<(), String> {
        let url = crate::attestation::parse_evidence_base_url(&self.base_url)?;
        if self.base_url.len() > 2048 || url.scheme() != "https" {
            return Err("evidence URL must be an HTTPS origin".into());
        }
        if let Some(host) = &self.connect_host {
            if host.is_empty() || host.len() > 253 {
                return Err("invalid evidence connection host".into());
            }
            url::Host::parse(host).map_err(|_| "invalid evidence connection host".to_owned())?;
        }
        Ok(())
    }
}

impl GatewaySettings {
    /// Validate the fields the process arguments cannot express. The startup
    /// argument checks bound the numeric limits.
    ///
    /// # Errors
    /// Returns an error for unsafe settings or inconsistent model lists.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(evidence) = &self.evidence {
            evidence.validate()?;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_rejects_unsafe_addresses() {
        for origin in [
            "http://api.example.test",
            "http://127.0.0.1",
            "https://user:password@api.example.test",
            "https://api.example.test/path",
            "https://api.example.test?query=1",
            "https://api.example.test#fragment",
            "file:///tmp/evidence",
        ] {
            let settings = EvidenceSettings {
                base_url: origin.into(),
                connect_host: None,
            };
            assert!(settings.validate().is_err(), "accepted {origin}");
        }
        for host in [
            "",
            "router:443",
            "https://router",
            "router/path",
            "user@router",
            "router?query=1",
        ] {
            let settings = EvidenceSettings {
                base_url: "https://api.example.test".into(),
                connect_host: Some(host.into()),
            };
            assert!(settings.validate().is_err(), "accepted {host}");
        }
        for host in [
            "c8s-router.c8s-system.svc.cluster.local",
            "127.0.0.1",
            "[::1]",
        ] {
            let settings = EvidenceSettings {
                base_url: "https://api.example.test".into(),
                connect_host: Some(host.into()),
            };
            assert!(settings.validate().is_ok(), "rejected {host}");
        }
    }
}
