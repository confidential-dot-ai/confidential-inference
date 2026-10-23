//! The key registry snapshot contract.
//!
//! The admin registry owns every API key. The gateway holds a copy of its
//! latest snapshot in memory (`crate::api_keys::KeyStore`). It pulls the
//! snapshot from the admin over HTTPS (`crate::admin_client`), and the admin
//! may also push it through `PUT /admin/v1/api-keys/snapshot`, which the
//! admin request check (`crate::admin_auth`) protects. This module holds
//! the wire types and the rules both paths share.
//!
//! The gateway never fails open. A refused snapshot leaves the cache
//! unchanged: the gateway keeps answering from the last accepted snapshot.
//!
//! ## The pepper rule
//!
//! Every snapshot states one `pepperFingerprint` in its envelope: the
//! pepper the admin minted every row with.
//!
//! - It matches the gateway's pepper: the snapshot is applied. A single row
//!   that names another pepper is still skipped and counted, because a
//!   rotation can leave one old row behind.
//! - It differs: the snapshot is refused with `pepper_mismatch` (a push
//!   answers `409`). The detail names the first 12 characters of each
//!   fingerprint. `gateway_key_registry_pepper_mismatch` reads 1 until a
//!   matching snapshot arrives.
//! - It is empty: the snapshot is applied and each row is judged alone.

use serde::{Deserialize, Serialize};

/// The schema this gateway build understands.
pub const SNAPSHOT_SCHEMA: &str = "confidential.ai/key-registry-snapshot/v1";

/// The largest number of keys one snapshot may carry.
pub const MAX_SNAPSHOT_KEYS: usize = 10_000;

/// One key row inside a snapshot body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySnapshotKey {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub prefix: String,
    pub key_hash: String,
    pub pepper_fingerprint: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Reserved. Always `null` in this release; the gateway accepts and
    /// ignores it.
    #[serde(default)]
    pub rate_limit: Option<serde_json::Value>,
    pub created_at: String,
    pub created_by: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    pub version: i64,
}

/// The body of a snapshot, pulled or pushed (`PUT /admin/v1/api-keys/snapshot`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotPush {
    pub schema_version: String,
    pub environment: String,
    pub revision: i64,
    #[serde(default)]
    pub generated_at: String,
    /// The fingerprint of the pepper the admin backend minted every row
    /// with. The gateway refuses the whole snapshot with `409
    /// pepper_mismatch` when this names a pepper it does not hold. An
    /// empty value states nothing and keeps the per-row rule.
    #[serde(default)]
    pub pepper_fingerprint: String,
    pub keys: Vec<RegistrySnapshotKey>,
}

/// The result of applying one snapshot; the body of a successful push.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotPushResult {
    /// The revision the push carried.
    pub revision: i64,
    /// The revision the gateway holds after the push.
    pub cached_revision: i64,
    /// The rows the gateway stored.
    pub accepted: i64,
    /// The rows the gateway skipped for a pepper fingerprint mismatch.
    pub skipped_pepper_mismatch: i64,
    /// `false` when the push repeated the cached revision. The gateway
    /// wrote nothing, and the admin VM may treat this as an
    /// acknowledgement.
    pub applied: bool,
}

/// Why the gateway refused one snapshot. A refused snapshot leaves the
/// cache unchanged.
#[derive(Debug, Eq, PartialEq)]
pub enum SnapshotError {
    /// The schema, the environment, the row count or a field value is wrong.
    Invalid,
    /// The revision is lower than the cached revision.
    StaleRevision,
    /// The snapshot names a pepper this gateway does not hold.
    PepperMismatch { expected: String, received: String },
}

impl SnapshotError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "invalid_request",
            Self::StaleRevision => "stale_revision",
            Self::PepperMismatch { .. } => "pepper_mismatch",
        }
    }
}

/// What the gateway does with one snapshot revision.
///
/// A strictly higher revision is applied. An equal revision is an
/// acknowledgement and changes nothing. A lower revision is refused, which
/// blocks a rollback of the key set. A restarted gateway holds no revision,
/// so its first snapshot may have any revision of at least 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionDecision {
    Apply,
    AlreadyHeld,
    Refuse,
}

#[must_use]
pub fn revision_decision(cached_revision: Option<i64>, revision: i64) -> RevisionDecision {
    let cached = cached_revision.unwrap_or(0);
    if revision > cached {
        RevisionDecision::Apply
    } else if revision == cached && cached_revision.is_some() {
        RevisionDecision::AlreadyHeld
    } else {
        RevisionDecision::Refuse
    }
}

/// Check one snapshot against the contract, before any change.
///
/// # Errors
///
/// Returns `SnapshotError::Invalid` when the schema version, the
/// environment name, the revision or the row count is wrong.
pub fn validate_push(push: &SnapshotPush, gateway_environment: &str) -> Result<(), SnapshotError> {
    if push.schema_version != SNAPSHOT_SCHEMA
        || (!gateway_environment.is_empty() && push.environment != gateway_environment)
        || push.revision < 1
        || push.keys.len() > MAX_SNAPSHOT_KEYS
    {
        return Err(SnapshotError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use axum::body::Body;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use http::{Request, StatusCode};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::{
        ApiKeyVerifier,
        api_keys::{KeyStore, admin_router},
    };

    use super::*;

    const KEY_ID: &str = "key_0123456789abcdef0123456789abcdef";

    fn gateway_pepper() -> Vec<u8> {
        vec![7_u8; 32]
    }

    fn pepper_fingerprint_hex(pepper: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"confidential.ai/gateway-pepper-fingerprint/v1");
        hasher.update(pepper);
        hex::encode(hasher.finalize())
    }

    fn plaintext_key_hash(pepper: &[u8], plaintext: &str) -> String {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<Sha256>::new_from_slice(pepper).unwrap_or_else(|_| unreachable!());
        mac.update(plaintext.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    fn store() -> Arc<KeyStore> {
        Arc::new(
            KeyStore::new(gateway_pepper(), "integration-staging")
                .unwrap_or_else(|error| panic!("{error:?}")),
        )
    }

    fn snapshot(revision: i64) -> serde_json::Value {
        let fingerprint = pepper_fingerprint_hex(&gateway_pepper());
        snapshot_with(
            revision,
            &plaintext_key_hash(&gateway_pepper(), "ci_example"),
            &fingerprint,
            &fingerprint,
        )
    }

    /// The envelope and the row fingerprint differ only in a test: the admin
    /// stamps the envelope with the pepper it minted every row with.
    fn snapshot_with(
        revision: i64,
        key_hash: &str,
        envelope_fingerprint: &str,
        fingerprint: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": SNAPSHOT_SCHEMA,
            "environment": "integration-staging",
            "revision": revision,
            "generatedAt": "2026-09-18T10:00:00Z",
            "pepperFingerprint": envelope_fingerprint,
            "keys": [{
                "id": KEY_ID,
                "name": "example",
                "owner": "unknown",
                "prefix": "ci_abcdefgh",
                "keyHash": key_hash,
                "pepperFingerprint": fingerprint,
                "tags": ["example"],
                "rateLimit": null,
                "createdAt": "2026-09-18T09:00:00Z",
                "createdBy": "operator@confidential.ai",
                "revokedAt": null,
                "revokedBy": null,
                "version": 1,
            }],
        })
    }

    fn apply(
        store: &KeyStore,
        body: &serde_json::Value,
    ) -> Result<SnapshotPushResult, SnapshotError> {
        store.apply(&serde_json::from_value(body.clone()).unwrap_or_else(|error| panic!("{error}")))
    }

    async fn push(
        store: &Arc<KeyStore>,
        body: &serde_json::Value,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn Error>> {
        let response = admin_router(store.clone())
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/admin/v1/api-keys/snapshot")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(body)?))?,
            )
            .await?;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    #[test]
    fn a_cold_start_holds_no_keys_and_is_not_ready() {
        let store = store();
        assert!(!store.is_ready());
        assert_eq!(store.cached_revision(), None);
        assert_eq!(store.verify("ci_example"), None);
    }

    #[test]
    fn a_snapshot_fills_the_cache_and_makes_the_store_ready() {
        let store = store();
        let result = apply(&store, &snapshot(1)).unwrap_or_else(|error| panic!("{error:?}"));
        assert!(result.applied);
        assert_eq!(result.accepted, 1);
        assert!(store.is_ready());
        assert_eq!(store.verify("ci_example"), Some(KEY_ID.to_owned()));
        assert_eq!(store.verify("ci_other"), None);
    }

    #[test]
    fn a_repeated_revision_is_acknowledged_and_changes_nothing() {
        let store = store();
        apply(&store, &snapshot(2)).unwrap_or_else(|error| panic!("{error:?}"));
        // The same revision with no rows must not empty the cache.
        let mut repeat = snapshot(2);
        repeat["keys"] = serde_json::json!([]);
        let result = apply(&store, &repeat).unwrap_or_else(|error| panic!("{error:?}"));
        assert!(!result.applied);
        assert_eq!(store.verify("ci_example"), Some(KEY_ID.to_owned()));
    }

    #[test]
    fn a_lower_revision_is_refused_and_leaves_the_cache_unchanged() {
        let store = store();
        apply(&store, &snapshot(5)).unwrap_or_else(|error| panic!("{error:?}"));
        let mut older = snapshot(4);
        older["keys"] = serde_json::json!([]);
        assert_eq!(apply(&store, &older), Err(SnapshotError::StaleRevision));
        assert_eq!(store.cached_revision(), Some(5));
        assert_eq!(store.verify("ci_example"), Some(KEY_ID.to_owned()));
    }

    #[test]
    fn a_wrong_schema_or_environment_is_refused() {
        let store = store();
        let mut wrong_schema = snapshot(1);
        wrong_schema["schemaVersion"] = serde_json::json!("confidential.ai/other/v9");
        assert_eq!(apply(&store, &wrong_schema), Err(SnapshotError::Invalid));
        let mut wrong_environment = snapshot(1);
        wrong_environment["environment"] = serde_json::json!("production");
        assert_eq!(
            apply(&store, &wrong_environment),
            Err(SnapshotError::Invalid)
        );
        assert_eq!(store.cached_revision(), None);
    }

    #[test]
    fn a_row_with_another_pepper_is_skipped_and_counted() {
        let store = store();
        let fingerprint = pepper_fingerprint_hex(&gateway_pepper());
        let other = pepper_fingerprint_hex(&[9_u8; 32]);
        let result = apply(
            &store,
            &snapshot_with(
                1,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &fingerprint,
                &other,
            ),
        )
        .unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(result.accepted, 0);
        assert_eq!(result.skipped_pepper_mismatch, 1);
        // The revision still advances, so the next snapshot is not refused.
        assert_eq!(store.cached_revision(), Some(1));
    }

    #[test]
    fn an_empty_envelope_fingerprint_keeps_the_per_row_rule() {
        let store = store();
        let mut body = snapshot(1);
        body["pepperFingerprint"] = serde_json::json!("");
        let result = apply(&store, &body).unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(result.accepted, 1);
    }

    #[test]
    fn one_bad_row_refuses_the_whole_snapshot() {
        let store = store();
        apply(&store, &snapshot(1)).unwrap_or_else(|error| panic!("{error:?}"));
        let mut broken = snapshot(2);
        let mut second = broken["keys"][0].clone();
        second["id"] = serde_json::json!("key_ffffffffffffffffffffffffffffffff");
        second["createdAt"] = serde_json::json!("not-a-timestamp");
        broken["keys"] = serde_json::json!([broken["keys"][0].clone(), second]);
        assert_eq!(apply(&store, &broken), Err(SnapshotError::Invalid));
        assert_eq!(store.cached_revision(), Some(1));
        assert_eq!(store.verify("ci_example"), Some(KEY_ID.to_owned()));
    }

    #[test]
    fn a_revoked_row_rejects_the_key_and_reports_it_revoked() {
        let store = store();
        apply(&store, &snapshot(1)).unwrap_or_else(|error| panic!("{error:?}"));
        let mut revoked = snapshot(2);
        revoked["keys"][0]["revokedAt"] = serde_json::json!("2026-09-18T10:00:00Z");
        revoked["keys"][0]["revokedBy"] = serde_json::json!("operator@confidential.ai");
        apply(&store, &revoked).unwrap_or_else(|error| panic!("{error:?}"));
        assert_eq!(store.verify("ci_example"), None);
        assert_eq!(store.verify_revoked("ci_example"), Some(KEY_ID.to_owned()));
    }

    #[tokio::test]
    async fn a_push_answers_with_the_result() -> Result<(), Box<dyn Error>> {
        let store = store();
        let (status, body) = push(&store, &snapshot(1)).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["applied"], serde_json::json!(true));
        assert_eq!(body["cachedRevision"], serde_json::json!(1));
        let (status, body) = push(&store, &snapshot(1)).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["applied"], serde_json::json!(false));
        Ok(())
    }

    #[tokio::test]
    async fn a_stale_or_invalid_push_answers_its_code() -> Result<(), Box<dyn Error>> {
        let store = store();
        push(&store, &snapshot(3)).await?;
        let (status, body) = push(&store, &snapshot(2)).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], serde_json::json!("stale_revision"));
        let mut invalid = snapshot(4);
        invalid["schemaVersion"] = serde_json::json!("confidential.ai/other/v9");
        let (status, body) = push(&store, &invalid).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], serde_json::json!("invalid_request"));
        Ok(())
    }

    #[tokio::test]
    async fn a_push_naming_another_pepper_is_refused_with_409() -> Result<(), Box<dyn Error>> {
        let store = store();
        push(&store, &snapshot(1)).await?;
        let fingerprint = pepper_fingerprint_hex(&gateway_pepper());
        let other_pepper = [9_u8; 32];
        let other = pepper_fingerprint_hex(&other_pepper);
        let mismatched = snapshot_with(
            2,
            &plaintext_key_hash(&other_pepper, "ci_other"),
            &other,
            &other,
        );
        let (status, body) = push(&store, &mismatched).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], serde_json::json!("pepper_mismatch"));
        // The detail names both prefixes, never a whole fingerprint.
        let detail = body["detail"].as_str().unwrap_or_default().to_owned();
        assert!(detail.contains(&fingerprint[..12]), "{detail}");
        assert!(detail.contains(&other[..12]), "{detail}");
        assert!(!detail.contains(fingerprint.as_str()), "{detail}");
        assert!(!detail.contains(other.as_str()), "{detail}");
        assert_eq!(store.cached_revision(), Some(1));
        assert_eq!(store.verify("ci_example"), Some(KEY_ID.to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn the_source_route_reports_the_drift_probe_fields() -> Result<(), Box<dyn Error>> {
        let store = store();
        push(&store, &snapshot(3)).await?;
        let response = admin_router(store)
            .oneshot(
                Request::builder()
                    .uri("/admin/v1/api-keys/source")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["cachedRevision"], serde_json::json!(3));
        assert_eq!(body["rowCount"], serde_json::json!(1));
        assert_eq!(
            body["pepperFingerprint"],
            serde_json::json!(pepper_fingerprint_hex(&gateway_pepper()))
        );
        Ok(())
    }

    #[test]
    fn the_revision_decision_separates_apply_hold_and_refuse() {
        assert_eq!(revision_decision(None, 1), RevisionDecision::Apply);
        assert_eq!(revision_decision(None, 0), RevisionDecision::Refuse);
        assert_eq!(revision_decision(Some(4), 5), RevisionDecision::Apply);
        assert_eq!(revision_decision(Some(4), 4), RevisionDecision::AlreadyHeld);
        assert_eq!(revision_decision(Some(4), 3), RevisionDecision::Refuse);
    }

    #[test]
    fn validate_push_checks_the_schema_the_environment_and_the_size() {
        let mut push = SnapshotPush {
            schema_version: SNAPSHOT_SCHEMA.to_owned(),
            environment: "integration-staging".to_owned(),
            revision: 1,
            generated_at: "2026-09-18T10:00:00Z".to_owned(),
            pepper_fingerprint: String::new(),
            keys: Vec::new(),
        };
        assert!(validate_push(&push, "integration-staging").is_ok());
        assert_eq!(
            validate_push(&push, "production"),
            Err(SnapshotError::Invalid)
        );
        push.revision = 0;
        assert_eq!(
            validate_push(&push, "integration-staging"),
            Err(SnapshotError::Invalid)
        );
        push.revision = 1;
        push.schema_version = "confidential.ai/other/v9".to_owned();
        assert_eq!(
            validate_push(&push, "integration-staging"),
            Err(SnapshotError::Invalid)
        );
    }
}
