//! The gateway's key registry snapshot contract.
//!
//! A key registry is an admin-owned store that holds API key hashes. The
//! admin VM owns every write to it. The admin VM pushes the complete
//! snapshot to this gateway through the signed admin channel. See
//! `docs/plans/api-keys-source-of-truth-admin.md` for the design.
//!
//! The gateway never calls the admin VM. The network permits no such call:
//! the admin VM reaches each gateway, and no gateway reaches the admin VM.
//! This module therefore holds no HTTP client and no poller. It holds the
//! snapshot wire types, the read mode, and the revision rule.
//!
//! The push route is `PUT /admin/v1/api-keys/snapshot`. It lives on the
//! admin router, so the existing ECDSA P-256 admin request signature
//! already binds the method, the path, the body hash, a timestamp and a
//! one-time nonce (`crate::admin_auth`). The snapshot carries no second
//! signature, and the gateway gains no new trust root.
//!
//! The gateway never fails open. A rejected push leaves the cache
//! unchanged: the gateway keeps answering from the last accepted snapshot.
//!
//! ## The pepper rule of the contract
//!
//! Every snapshot states one `pepperFingerprint` in its envelope. That
//! field names the pepper the admin backend minted every row with.
//!
//! The gateway compares the envelope fingerprint with its own pepper
//! fingerprint before it writes anything.
//!
//! - The two agree: the gateway applies the snapshot. A single row that
//!   names another pepper is still skipped and counted, because a
//!   rotation can leave one old row behind.
//! - The two differ: the gateway answers `409` with the code
//!   `pepper_mismatch` and writes nothing. Every row of such a snapshot
//!   carries a hash the gateway can never match, so applying it would
//!   replace a working cache with rows that authenticate nothing. The
//!   `detail` field names the first 12 characters of each fingerprint, so
//!   an operator sees which side is stale. The gauge
//!   `gateway_key_registry_pepper_mismatch` reads 1 until a matching
//!   snapshot arrives.
//! - The envelope states an empty fingerprint: the gateway applies the
//!   snapshot and judges each row on its own. An older admin backend
//!   sends an empty field, so this case stays compatible.
//!
//! `GET /admin/v1/api-keys/source` is unchanged. It still reports this
//! gateway's own `pepperFingerprint`, which is how the admin backend and
//! the deploy tooling read the gateway's side of the comparison.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// The schema this gateway build understands. A push that names a
/// different schema is rejected and the cache is unchanged.
pub const SNAPSHOT_SCHEMA: &str = "confidential.ai/key-registry-snapshot/v1";

/// The largest number of keys one pushed snapshot may carry.
///
/// The admin channel already caps a request body at one mebibyte
/// (`crate::admin_auth::MAX_ADMIN_BODY_BYTES`). This second limit states
/// the row count plainly, so an oversized push fails with a clear code
/// instead of a body-size rejection.
pub const MAX_SNAPSHOT_KEYS: usize = 10_000;

/// How the gateway answers an API key verification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum KeyRegistryMode {
    /// Answer from the `api_keys` table alone. A pushed snapshot is still
    /// stored, but it never answers a request.
    #[default]
    Local,
    /// Check `api_keys` first, then the pushed snapshot.
    Dual,
    /// Answer from the pushed snapshot alone. A local mint is disabled.
    Registry,
}

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

/// The body of `PUT /admin/v1/api-keys/snapshot`.
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

/// The body of a successful `PUT /admin/v1/api-keys/snapshot`.
#[derive(Clone, Copy, Debug, Serialize)]
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

/// Why the gateway refused one pushed snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SnapshotRejection {
    /// The push repeats a revision the gateway already passed. The admin
    /// VM must not retry it; the next drift probe resolves the difference.
    StaleRevision,
    /// The schema, the environment, or a field value is wrong.
    Invalid,
    /// The snapshot names a pepper this gateway does not hold. The admin
    /// VM must not retry it: no row of that snapshot can ever match.
    PepperMismatch,
}

/// Decide what the gateway does with one pushed revision.
///
/// A strictly higher revision is applied. An equal revision is an
/// acknowledgement and writes nothing. A lower revision is refused, which
/// blocks a rollback of the key set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionDecision {
    Apply,
    AlreadyHeld,
    Refuse,
}

/// Compare a pushed revision against the cached revision.
#[must_use]
pub fn revision_decision(cached_revision: Option<i64>, pushed_revision: i64) -> RevisionDecision {
    let cached = cached_revision.unwrap_or(0);
    if pushed_revision > cached {
        RevisionDecision::Apply
    } else if pushed_revision == cached && cached_revision.is_some() {
        RevisionDecision::AlreadyHeld
    } else {
        RevisionDecision::Refuse
    }
}

/// A snapshot is applied only when its revision is strictly higher than
/// the cached revision.
#[must_use]
pub fn accepts_revision(cached_revision: Option<i64>, snapshot_revision: i64) -> bool {
    snapshot_revision > cached_revision.unwrap_or(0)
}

/// Check one pushed snapshot against the frozen contract, before any
/// write.
///
/// # Errors
///
/// Returns `SnapshotRejection::Invalid` when the schema version, the
/// environment name, the revision or the row count is wrong.
pub fn validate_push(
    push: &SnapshotPush,
    gateway_environment: &str,
) -> Result<(), SnapshotRejection> {
    if push.schema_version != SNAPSHOT_SCHEMA {
        return Err(SnapshotRejection::Invalid);
    }
    if !gateway_environment.is_empty() && push.environment != gateway_environment {
        return Err(SnapshotRejection::Invalid);
    }
    if push.revision < 1 || push.keys.len() > MAX_SNAPSHOT_KEYS {
        return Err(SnapshotRejection::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use axum::body::Body;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use http::{Request, StatusCode};
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use crate::api_keys::{GatewayState, admin_router};

    use super::*;

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

    fn state_with_mode(mode: KeyRegistryMode) -> Result<GatewayState, Box<dyn Error>> {
        Ok(
            GatewayState::open(tempfile::NamedTempFile::new()?.path(), gateway_pepper())
                .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
                .with_mode(mode)
                .with_environment("integration-staging"),
        )
    }

    fn snapshot_json(revision: i64, key_hash: &str, fingerprint: &str) -> serde_json::Value {
        snapshot_json_with(revision, key_hash, fingerprint, fingerprint)
    }

    /// Build a snapshot whose envelope fingerprint and row fingerprint may
    /// differ. The two differ only in a test: the admin backend stamps the
    /// envelope with the pepper it minted every row with.
    fn snapshot_json_with(
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
                "id": "key_0123456789abcdef0123456789abcdef",
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

    async fn push(
        state: &GatewayState,
        body: &serde_json::Value,
    ) -> Result<(StatusCode, serde_json::Value), Box<dyn Error>> {
        let response = admin_router(state.clone())
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

    #[tokio::test]
    async fn a_pushed_snapshot_updates_the_cache() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        assert!(!state.registry_ready());

        let (status, body) = push(&state, &snapshot_json(1, &key_hash, &fingerprint)).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["applied"], serde_json::json!(true));
        assert_eq!(body["accepted"], serde_json::json!(1));
        assert_eq!(body["cachedRevision"], serde_json::json!(1));
        assert!(state.registry_ready());
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_repeated_revision_is_acknowledged_and_writes_nothing() -> Result<(), Box<dyn Error>>
    {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        push(&state, &snapshot_json(2, &key_hash, &fingerprint)).await?;

        // The same revision arrives again, with no rows. The gateway must
        // not empty its cache: it recognises the revision it already holds.
        let mut repeat = snapshot_json(2, &key_hash, &fingerprint);
        repeat["keys"] = serde_json::json!([]);
        let (status, body) = push(&state, &repeat).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["applied"], serde_json::json!(false));
        assert_eq!(body["cachedRevision"], serde_json::json!(2));
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_lower_revision_is_refused_and_leaves_the_cache_unchanged()
    -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        push(&state, &snapshot_json(5, &key_hash, &fingerprint)).await?;

        let mut older = snapshot_json(4, &key_hash, &fingerprint);
        older["keys"] = serde_json::json!([]);
        let (status, body) = push(&state, &older).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], serde_json::json!("stale_revision"));
        assert_eq!(state.registry_cached_revision()?, Some(5));
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_wrong_schema_or_environment_is_refused() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;

        let mut wrong_schema = snapshot_json(1, &key_hash, &fingerprint);
        wrong_schema["schemaVersion"] = serde_json::json!("confidential.ai/other/v9");
        let (status, _) = push(&state, &wrong_schema).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let mut wrong_environment = snapshot_json(1, &key_hash, &fingerprint);
        wrong_environment["environment"] = serde_json::json!("production");
        let (status, _) = push(&state, &wrong_environment).await?;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        assert_eq!(state.registry_cached_revision()?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_wrong_pepper_fingerprint_row_is_skipped_and_counted() -> Result<(), Box<dyn Error>> {
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        let fingerprint = pepper_fingerprint_hex(&gateway_pepper());
        let other_fingerprint = pepper_fingerprint_hex(&[9_u8; 32]);
        // The envelope names the gateway's own pepper, so the snapshot is
        // accepted. One row names another pepper, so that row is skipped.
        let (status, body) = push(
            &state,
            &snapshot_json_with(
                1,
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                &fingerprint,
                &other_fingerprint,
            ),
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accepted"], serde_json::json!(0));
        assert_eq!(body["skippedPepperMismatch"], serde_json::json!(1));
        // The revision still advances, so the next push is not refused.
        assert_eq!(state.registry_cached_revision()?, Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn a_snapshot_naming_another_pepper_is_refused_with_409() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        push(&state, &snapshot_json(1, &key_hash, &fingerprint)).await?;

        let other_pepper = [9_u8; 32];
        let other_fingerprint = pepper_fingerprint_hex(&other_pepper);
        let mismatched = snapshot_json_with(
            2,
            &plaintext_key_hash(&other_pepper, "ci_other"),
            &other_fingerprint,
            &other_fingerprint,
        );
        let (status, body) = push(&state, &mismatched).await?;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], serde_json::json!("pepper_mismatch"));

        // The detail names both fingerprint prefixes, so an operator sees
        // which side is stale without a second request.
        let detail = body["detail"].as_str().unwrap_or_default().to_owned();
        assert!(detail.contains(&fingerprint[..12]), "{detail}");
        assert!(detail.contains(&other_fingerprint[..12]), "{detail}");
        // The detail never carries a whole fingerprint of either pepper.
        assert!(!detail.contains(fingerprint.as_str()), "{detail}");
        assert!(!detail.contains(other_fingerprint.as_str()), "{detail}");

        // The cache is exactly as it was. The refused snapshot applied no
        // row, so the working key still answers.
        assert_eq!(state.registry_cached_revision()?, Some(1));
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_empty_envelope_fingerprint_keeps_the_per_row_rule() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;

        // An older admin backend states no envelope fingerprint. The
        // gateway must still accept the snapshot and judge each row.
        let mut older_sender = snapshot_json(1, &key_hash, &fingerprint);
        older_sender["pepperFingerprint"] = serde_json::json!("");
        let (status, body) = push(&state, &older_sender).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["accepted"], serde_json::json!(1));
        Ok(())
    }

    #[tokio::test]
    async fn the_whole_snapshot_applies_in_one_transaction() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        push(&state, &snapshot_json(1, &key_hash, &fingerprint)).await?;

        // The second row carries an unparsable timestamp. The transaction
        // must roll back, so the first snapshot still answers.
        let mut broken = snapshot_json(2, &key_hash, &fingerprint);
        let mut second = broken["keys"][0].clone();
        second["id"] = serde_json::json!("key_ffffffffffffffffffffffffffffffff");
        second["createdAt"] = serde_json::json!("not-a-timestamp");
        broken["keys"] = serde_json::json!([broken["keys"][0].clone(), second]);
        let (status, _) = push(&state, &broken).await?;
        assert_ne!(status, StatusCode::OK);
        assert_eq!(state.registry_cached_revision()?, Some(1));
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_restart_keeps_the_pushed_snapshot() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let file = tempfile::NamedTempFile::new()?;
        let database_path = file.path().to_path_buf();
        {
            let state = GatewayState::open(&database_path, pepper.clone())
                .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
                .with_mode(KeyRegistryMode::Registry)
                .with_environment("integration-staging");
            push(&state, &snapshot_json(1, &key_hash, &fingerprint)).await?;
        }
        // Simulate a restart: reopen the same database file. The admin VM
        // is unreachable from here, and the cache must still answer.
        let restarted = GatewayState::open(&database_path, pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        assert!(restarted.registry_ready());
        assert_eq!(
            restarted.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[test]
    fn a_cold_start_with_no_snapshot_reports_not_ready() -> Result<(), Box<dyn Error>> {
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        assert!(!state.registry_ready());
        assert_eq!(state.verify("anything"), None);
        Ok(())
    }

    #[tokio::test]
    async fn registry_mode_refuses_a_local_mint() -> Result<(), Box<dyn Error>> {
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        let response = admin_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/api-keys")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "0123456789abcdef0123")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "name": "refused",
                        "tags": [],
                        "audit": {"actor": "operator", "reason": "registry mode test"},
                    }))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        Ok(())
    }

    #[tokio::test]
    async fn dual_mode_accepts_a_local_key_and_a_pushed_key() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let registry_key_hash = plaintext_key_hash(&pepper, "ci_registry_key");
        let state = state_with_mode(KeyRegistryMode::Dual)?;
        let mut body = snapshot_json(1, &registry_key_hash, &fingerprint);
        body["keys"][0]["id"] = serde_json::json!("key_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        body["keys"][0]["prefix"] = serde_json::json!("ci_regist");
        push(&state, &body).await?;
        assert_eq!(
            state.verify_with_source("ci_registry_key"),
            Some((
                "key_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                "registry"
            ))
        );

        // A key minted through the admin API is a `local` row and must
        // still verify in dual mode.
        let response = admin_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/api-keys")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "0123456789abcdef0123")
                    .body(Body::from(serde_json::to_vec(&serde_json::json!({
                        "name": "local key",
                        "tags": [],
                        "audit": {"actor": "operator", "reason": "dual-mode test"},
                    }))?))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        let minted: serde_json::Value = serde_json::from_slice(&bytes)?;
        let plaintext = minted["apiKey"].as_str().unwrap_or_default().to_owned();
        assert_eq!(
            state
                .verify_with_source(&plaintext)
                .map(|(_, source)| source),
            Some("local")
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_pushed_revoke_rejects_the_key() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Registry)?;
        push(&state, &snapshot_json(1, &key_hash, &fingerprint)).await?;
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );

        let mut revoked = snapshot_json(2, &key_hash, &fingerprint);
        revoked["keys"][0]["revokedAt"] = serde_json::json!("2026-09-18T10:00:00Z");
        revoked["keys"][0]["revokedBy"] = serde_json::json!("operator@confidential.ai");
        revoked["keys"][0]["version"] = serde_json::json!(2);
        let (status, _) = push(&state, &revoked).await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(state.verify("ci_example"), None);
        Ok(())
    }

    #[tokio::test]
    async fn the_source_route_reports_the_drift_probe_fields() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = state_with_mode(KeyRegistryMode::Dual)?;
        push(&state, &snapshot_json(3, &key_hash, &fingerprint)).await?;

        let response = admin_router(state)
            .oneshot(
                Request::builder()
                    .uri("/admin/v1/api-keys/source")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        let body: serde_json::Value = serde_json::from_slice(&bytes)?;
        assert_eq!(body["mode"], serde_json::json!("dual"));
        assert_eq!(body["cachedRevision"], serde_json::json!(3));
        assert_eq!(body["rowCount"], serde_json::json!(1));
        assert_eq!(body["pepperFingerprint"], serde_json::json!(fingerprint));
        Ok(())
    }

    #[test]
    fn accepts_revision_requires_a_strictly_higher_value() {
        assert!(accepts_revision(None, 1));
        assert!(accepts_revision(Some(1), 2));
        assert!(!accepts_revision(Some(2), 2));
        assert!(!accepts_revision(Some(3), 2));
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
            Err(SnapshotRejection::Invalid)
        );
        push.revision = 0;
        assert_eq!(
            validate_push(&push, "integration-staging"),
            Err(SnapshotRejection::Invalid)
        );
        push.revision = 1;
        push.schema_version = "confidential.ai/other/v9".to_owned();
        assert_eq!(
            validate_push(&push, "integration-staging"),
            Err(SnapshotRejection::Invalid)
        );
    }
}
