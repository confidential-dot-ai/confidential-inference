//! Release references derived from local, exact release asset bytes.
//! Deployment verifies signatures before publishing these files. A client
//! still verifies the release signature and its build evidence independently.
//! The gateway reads the selection once at start; the chart rolls the pods
//! when it changes.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use crate::{AttestationError, AttestationProvider};

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseReference {
    pub id: String,
    pub url: String,
    pub bundle_sha256: String,
    #[serde(skip)]
    pub policy_sha256: String,
}

pub struct ReleaseSettings {
    selected: ReleaseReference,
    releases: Vec<ReleaseReference>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Document {
    schema_version: u32,
    selected_bundle_sha256: String,
    // Each string preserves the exact signed asset bytes, including its
    // whitespace. The deployment tool writes this document, not a human.
    release_bundles: Vec<String>,
}

impl<'de> Deserialize<'de> for ReleaseSettings {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::compile(Document::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

fn digest_valid(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl ReleaseSettings {
    #[must_use]
    pub fn selected(&self) -> &ReleaseReference {
        &self.selected
    }
    fn compile(document: Document) -> Result<Self, String> {
        if document.schema_version != 1
            || document.release_bundles.is_empty()
            || document.release_bundles.len() > 8
        {
            return Err("invalid release selection document".into());
        }
        let mut releases = Vec::new();
        let mut hashes = std::collections::BTreeSet::new();
        for bytes in document.release_bundles {
            if bytes.len() > 256 * 1024 {
                return Err("release bundle exceeds its byte limit".into());
            }
            let bundle: Value =
                serde_json::from_str(&bytes).map_err(|_| "invalid release bundle JSON")?;
            if bundle["schema"] != "confidential.ai/release-manifest/v1" {
                return Err("invalid release bundle schema".into());
            }
            let id = bundle["release"]["name"]
                .as_str()
                .ok_or("release bundle has no name")?;
            if id.is_empty()
                || id.len() > 128
                || !id.as_bytes()[0].is_ascii_alphanumeric()
                || !id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            {
                return Err("invalid release bundle name".into());
            }
            let policy = bundle["allowlist"]["sha256"]
                .as_str()
                .filter(|value| digest_valid(value))
                .ok_or("invalid release policy digest")?;
            let hash = format!("sha256:{:x}", Sha256::digest(bytes.as_bytes()));
            if !hashes.insert(hash.clone()) {
                return Err("repeated release bundle".into());
            }
            releases.push(ReleaseReference { id: id.into(),
                url: format!("https://github.com/confidential-dot-ai/confidential-inference/releases/tag/{id}"),
                bundle_sha256: hash, policy_sha256: policy.into() });
        }
        let selected = releases
            .iter()
            .find(|release| release.bundle_sha256 == document.selected_bundle_sha256)
            .cloned()
            .ok_or("selected release bundle is absent")?;
        Ok(Self { selected, releases })
    }

    fn matching(&self, policy: &str) -> Option<&ReleaseReference> {
        if self.selected.policy_sha256 == policy {
            return Some(&self.selected);
        }
        let mut matching = self
            .releases
            .iter()
            .filter(|release| release.policy_sha256 == policy);
        let first = matching.next()?;
        // A policy can belong to several releases. Never guess a version.
        if matching.next().is_some() {
            None
        } else {
            Some(first)
        }
    }
}

/// Select a release after the cached CDS read, so a cached response never
/// claims the wrong release for its policy.
pub struct ReleaseMetadataProvider {
    pub policy: Arc<dyn AttestationProvider>,
    pub releases: ReleaseSettings,
}

#[async_trait::async_trait]
impl AttestationProvider for ReleaseMetadataProvider {
    fn requires_nonce(&self) -> bool {
        false
    }

    async fn response(&self, nonce: &[u8; 32]) -> Result<Value, AttestationError> {
        let mut response = self.policy.response(nonce).await?;
        let policy = response["c8s"]["activeAllowlist"]["sha256"]
            .as_str()
            .ok_or_else(|| AttestationError::Invalid("CDS metadata has no policy digest".into()))?;
        let settings = &self.releases;
        let matched = settings.matching(policy);
        let selection = json!({"status": if settings.selected.policy_sha256 == policy { "matched" } else { "pending" },
            "desired": settings.selected, "desiredPolicySha256": settings.selected.policy_sha256,
            "observedPolicySha256": policy});
        response["release"] = matched.map_or(Value::Null, |release| json!(release));
        response["releaseSelection"] = selection;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bundle(name: &str, policy: &str) -> String {
        json!({"schema":"confidential.ai/release-manifest/v1", "release":{"name":name},
            "allowlist":{"sha256":policy}})
        .to_string()
    }
    #[test]
    fn exact_bytes_derive_the_reference_and_same_policy_uses_explicit_selection()
    -> Result<(), String> {
        let policy = format!("sha256:{}", "a".repeat(64));
        let first = bundle("v0.14.17", &policy);
        let second = format!("{}\n", bundle("v0.14.18", &policy));
        let selected = format!("sha256:{:x}", Sha256::digest(second.as_bytes()));
        let settings = ReleaseSettings::compile(Document {
            schema_version: 1,
            selected_bundle_sha256: selected.clone(),
            release_bundles: vec![first, second],
        })?;
        assert_eq!(
            settings
                .matching(&policy)
                .map(|release| release.id.as_str()),
            Some("v0.14.18")
        );
        assert_eq!(settings.selected.bundle_sha256, selected);
        assert!(
            settings
                .matching(&format!("sha256:{}", "b".repeat(64)))
                .is_none()
        );
        Ok(())
    }
    #[tokio::test]
    async fn unmatched_policy_is_pending_without_a_false_release_claim()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Policy;
        #[async_trait::async_trait]
        impl AttestationProvider for Policy {
            async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
                Ok(
                    json!({"release":{"id":"unmatched"},"c8s":{"activeAllowlist":{"sha256":format!("sha256:{}", "b".repeat(64))}}}),
                )
            }
        }
        let asset = bundle("v0.14.18", &format!("sha256:{}", "a".repeat(64)));
        let provider = ReleaseMetadataProvider {
            policy: Arc::new(Policy),
            releases: serde_json::from_value(json!({"schemaVersion":1,
            "selectedBundleSha256":format!("sha256:{:x}",Sha256::digest(asset.as_bytes())),
            "releaseBundles":[asset]}))?,
        };
        let response = provider
            .response(&[0; 32])
            .await
            .map_err(|_| "metadata failed")?;
        assert!(response["release"].is_null());
        assert_eq!(response["releaseSelection"]["status"], "pending");
        assert_eq!(response["releaseSelection"]["desired"]["id"], "v0.14.18");
        Ok(())
    }
}
