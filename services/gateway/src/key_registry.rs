//! The gateway's key registry snapshot poller.
//!
//! A key registry is an admin-owned service that stores API key hashes. This
//! module polls its snapshot route, checks its signature, and applies an
//! accepted snapshot to the gateway's own cache. See
//! `docs/plans/api-keys-source-of-truth-admin.md` for the full design and
//! the frozen snapshot contract it implements.
//!
//! The poller never fails open. A fetch error, a bad signature, a bad
//! revision, or an unreachable registry leaves the cache unchanged: the
//! gateway keeps answering from the last accepted snapshot.

use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::ValueEnum;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{api_keys::GatewayState, metrics::GatewayMetrics};

/// The schema this gateway build understands. A registry that serves a
/// different schema is treated as a fetch error: the cache is unchanged.
pub const SNAPSHOT_SCHEMA: &str = "confidential.ai/key-registry-snapshot/v1";

/// How the gateway answers an API key verification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum KeyRegistryMode {
    /// Answer from the `api_keys` table alone. The poller never runs.
    #[default]
    Local,
    /// Check `api_keys` first, then the registry cache.
    Dual,
    /// Answer from the registry cache alone.
    Registry,
}

/// Static configuration for one poller.
#[derive(Clone, Debug)]
pub struct KeyRegistryConfig {
    pub mode: KeyRegistryMode,
    pub url: String,
    pub poll_seconds: u64,
    pub environment: String,
}

/// One key row inside a snapshot body, as CONTRACT.md section 2 defines it.
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotBody {
    schema_version: String,
    environment: String,
    revision: i64,
    keys: Vec<RegistrySnapshotKey>,
}

#[derive(Debug, PartialEq, Eq)]
enum PollOutcome {
    Applied {
        revision: i64,
        accepted: i64,
        skipped_pepper_mismatch: i64,
    },
    NotModified,
}

/// The canonical string the admin backend signs for one snapshot, per
/// CONTRACT.md section 3.
#[must_use]
pub fn canonical_snapshot_string(
    environment: &str,
    revision: i64,
    body_sha256_hex: &str,
) -> String {
    format!("v1\n{environment}\n{revision}\n{body_sha256_hex}\n")
}

/// Verify a snapshot signature against the admin signer public key.
///
/// # Errors
///
/// Returns `"invalid_signature"` when the signature does not verify or
/// cannot be decoded.
pub fn verify_snapshot_signature(
    public_key: &[u8],
    environment: &str,
    revision: i64,
    body: &[u8],
    signature_base64url: &str,
) -> Result<(), &'static str> {
    let body_hash = hex::encode(Sha256::digest(body));
    let canonical = canonical_snapshot_string(environment, revision, &body_hash);
    let signature = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| "invalid_signature")?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key)
        .verify(canonical.as_bytes(), &signature)
        .map_err(|_| "invalid_signature")
}

/// A snapshot is accepted only when its revision is strictly higher than the
/// cached revision. A 304 is the normal no-change path and never reaches
/// this function.
#[must_use]
pub fn accepts_revision(cached_revision: Option<i64>, snapshot_revision: i64) -> bool {
    snapshot_revision > cached_revision.unwrap_or(0)
}

/// Polls one environment's key registry snapshot route on an interval.
pub struct KeyRegistryPoller {
    client: reqwest::Client,
    config: KeyRegistryConfig,
    token: String,
    admin_public_key: Arc<Vec<u8>>,
    state: GatewayState,
    metrics: Arc<GatewayMetrics>,
}

impl KeyRegistryPoller {
    #[must_use]
    pub fn new(
        config: KeyRegistryConfig,
        token: String,
        admin_public_key: Arc<Vec<u8>>,
        state: GatewayState,
        metrics: Arc<GatewayMetrics>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
            token,
            admin_public_key,
            state,
            metrics,
        }
    }

    /// Start the poll loop. Returns `None` for `local` mode, which never
    /// polls.
    #[must_use]
    pub fn spawn(self) -> Option<tokio::task::JoinHandle<()>> {
        if self.config.mode == KeyRegistryMode::Local {
            return None;
        }
        Some(tokio::spawn(async move { self.run().await }))
    }

    async fn run(self) {
        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.poll_seconds.max(1)));
        loop {
            interval.tick().await;
            match self.poll_once().await {
                Ok(PollOutcome::Applied {
                    revision,
                    accepted,
                    skipped_pepper_mismatch,
                }) => {
                    self.metrics.set_key_registry_revision(revision);
                    self.metrics.set_key_registry_pepper_mismatch_rows(
                        u64::try_from(skipped_pepper_mismatch).unwrap_or(0),
                    );
                    self.metrics.set_key_registry_stale_seconds(0.0);
                    tracing::info!(
                        revision,
                        accepted,
                        skipped_pepper_mismatch,
                        "applied a key registry snapshot"
                    );
                }
                Ok(PollOutcome::NotModified) => {
                    self.refresh_stale_metric();
                }
                Err(reason) => {
                    self.metrics.record_key_registry_pull_failure(reason);
                    self.refresh_stale_metric();
                    tracing::warn!(
                        reason,
                        "the key registry poll failed; the cache is unchanged"
                    );
                }
            }
        }
    }

    fn refresh_stale_metric(&self) {
        let Ok(status) = self.state.registry_source_status() else {
            return;
        };
        let Some(stale_seconds) = status.stale_seconds else {
            return;
        };
        self.metrics
            .set_key_registry_stale_seconds(f64_from_i64(stale_seconds));
        if stale_seconds > 300 {
            tracing::warn!(
                stale_seconds,
                "no successful key registry fetch in over five minutes"
            );
        }
    }

    async fn poll_once(&self) -> Result<PollOutcome, &'static str> {
        let cached_revision = self
            .state
            .registry_cached_revision()
            .map_err(|_| "database_unavailable")?;
        let url = format!(
            "{}/registry/v1/{}/keys",
            self.config.url.trim_end_matches('/'),
            self.config.environment
        );
        let mut request = self.client.get(url).bearer_auth(&self.token);
        if let Some(revision) = cached_revision {
            request = request.header(reqwest::header::IF_NONE_MATCH, format!("\"{revision}\""));
        }
        let response = request.send().await.map_err(|_| "fetch_error")?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(PollOutcome::NotModified);
        }
        if !response.status().is_success() {
            return Err("http_error");
        }
        let signature_version =
            header_text(&response, "x-registry-signature-version").ok_or("missing_signature")?;
        if signature_version != "v1" {
            return Err("unsupported_signature_version");
        }
        let signature = header_text(&response, "x-registry-signature")
            .ok_or("missing_signature")?
            .to_owned();
        let body = response.bytes().await.map_err(|_| "fetch_error")?;
        let snapshot: SnapshotBody = serde_json::from_slice(&body).map_err(|_| "invalid_body")?;
        if snapshot.schema_version != SNAPSHOT_SCHEMA
            || snapshot.environment != self.config.environment
        {
            return Err("invalid_body");
        }
        verify_snapshot_signature(
            &self.admin_public_key,
            &self.config.environment,
            snapshot.revision,
            &body,
            &signature,
        )
        .map_err(|_| "bad_signature")?;
        if !accepts_revision(cached_revision, snapshot.revision) {
            return Err("stale_revision");
        }
        let outcome = self
            .state
            .apply_registry_snapshot(&self.config.environment, snapshot.revision, &snapshot.keys)
            .map_err(|_| "apply_failed")?;
        Ok(PollOutcome::Applied {
            revision: snapshot.revision,
            accepted: outcome.accepted,
            skipped_pepper_mismatch: outcome.skipped_pepper_mismatch,
        })
    }
}

fn header_text<'a>(response: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    response.headers().get(name)?.to_str().ok()
}

fn f64_from_i64(value: i64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let converted = value as f64;
    converted
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        io::{Read, Write},
        net::TcpListener,
        process::Command,
    };

    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;

    use crate::admin_auth::AdminRequestVerifier;

    use super::*;

    fn run(command: &mut Command) -> Result<(), Box<dyn Error>> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        Ok(())
    }

    struct SigningKey {
        certificate: std::path::PathBuf,
        key: std::path::PathBuf,
        _directory: tempfile::TempDir,
    }

    fn generate_signing_key() -> Result<SigningKey, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key = directory.path().join("registry-signer.key");
        let certificate = directory.path().join("registry-signer.crt");
        run(Command::new("openssl")
            .args([
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
            ])
            .arg(&key))?;
        run(Command::new("openssl")
            .args(["req", "-x509", "-new", "-key"])
            .arg(&key)
            .args([
                "-sha256",
                "-days",
                "1",
                "-subj",
                "/CN=registry-signer",
                "-out",
            ])
            .arg(&certificate))?;
        Ok(SigningKey {
            certificate,
            key,
            _directory: directory,
        })
    }

    fn sign(key: &SigningKey, message: &[u8]) -> Result<String, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let message_path = directory.path().join("message");
        let signature_path = directory.path().join("signature");
        std::fs::write(&message_path, message)?;
        run(Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&key.key)
            .arg("-out")
            .arg(&signature_path)
            .arg(&message_path))?;
        Ok(URL_SAFE_NO_PAD.encode(std::fs::read(signature_path)?))
    }

    fn snapshot_body(
        environment: &str,
        revision: i64,
        key_hash: &str,
        pepper_fingerprint: &str,
    ) -> Vec<u8> {
        let value = serde_json::json!({
            "schemaVersion": SNAPSHOT_SCHEMA,
            "environment": environment,
            "revision": revision,
            "generatedAt": "2026-09-18T10:00:00Z",
            "pepperFingerprint": pepper_fingerprint,
            "keys": [{
                "id": "key_0123456789abcdef0123456789abcdef",
                "name": "example",
                "owner": "unknown",
                "prefix": "ci_abcdefgh",
                "keyHash": key_hash,
                "pepperFingerprint": pepper_fingerprint,
                "tags": ["example"],
                "rateLimit": null,
                "createdAt": "2026-09-18T09:00:00Z",
                "createdBy": "operator@confidential.ai",
                "revokedAt": null,
                "revokedBy": null,
                "version": 1,
            }],
        });
        serde_json::to_vec(&value).unwrap_or_else(|_| unreachable!())
    }

    /// A one-shot fake HTTP/1.1 server: it accepts one connection, ignores
    /// the request, and writes back the exact response bytes given.
    fn one_shot_server(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|_| unreachable!());
        let addr = listener.local_addr().unwrap_or_else(|_| unreachable!());
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0_u8; 8_192];
                let _ = stream.read(&mut buffer);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://{addr}")
    }

    fn ok_response(body: &[u8], revision: i64, signature: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nEtag: \"{revision}\"\r\nX-Registry-Signature-Version: v1\r\nX-Registry-Signature: {signature}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }

    fn not_modified_response(revision: i64) -> Vec<u8> {
        format!("HTTP/1.1 304 Not Modified\r\nEtag: \"{revision}\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .into_bytes()
    }

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

    fn poller(url: String, public_key: Arc<Vec<u8>>, state: GatewayState) -> KeyRegistryPoller {
        KeyRegistryPoller::new(
            KeyRegistryConfig {
                mode: KeyRegistryMode::Registry,
                url,
                poll_seconds: 10,
                environment: "integration-staging".to_owned(),
            },
            "registry-token".to_owned(),
            public_key,
            state,
            Arc::new(GatewayMetrics::new("integration-staging")),
        )
    }

    #[tokio::test]
    async fn a_valid_signature_updates_the_cache() -> Result<(), Box<dyn Error>> {
        let signing_key = generate_signing_key()?;
        let verifier = AdminRequestVerifier::from_certificate_file(&signing_key.certificate)
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        let public_key = verifier.public_key_bytes();
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let body = snapshot_body("integration-staging", 1, &key_hash, &fingerprint);
        let body_hash = hex::encode(Sha256::digest(&body));
        let canonical = canonical_snapshot_string("integration-staging", 1, &body_hash);
        let signature = sign(&signing_key, canonical.as_bytes())?;
        let url = one_shot_server(ok_response(&body, 1, &signature));

        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper.clone())
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        let poller = poller(url, public_key, state.clone());
        let outcome = poller.poll_once().await;
        assert!(matches!(
            outcome,
            Ok(PollOutcome::Applied {
                revision: 1,
                accepted: 1,
                skipped_pepper_mismatch: 0
            })
        ));
        assert_eq!(state.registry_cached_revision()?, Some(1));
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_bad_signature_leaves_the_cache_unchanged() -> Result<(), Box<dyn Error>> {
        let signing_key = generate_signing_key()?;
        let other_key = generate_signing_key()?;
        let verifier = AdminRequestVerifier::from_certificate_file(&signing_key.certificate)
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        let public_key = verifier.public_key_bytes();
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let body = snapshot_body("integration-staging", 1, &key_hash, &fingerprint);
        let body_hash = hex::encode(Sha256::digest(&body));
        let canonical = canonical_snapshot_string("integration-staging", 1, &body_hash);
        // Signed with a different key than the one the gateway trusts.
        let signature = sign(&other_key, canonical.as_bytes())?;
        let url = one_shot_server(ok_response(&body, 1, &signature));

        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        let poller = poller(url, public_key, state.clone());
        assert_eq!(poller.poll_once().await, Err("bad_signature"));
        assert_eq!(state.registry_cached_revision()?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_lower_or_equal_revision_leaves_the_cache_unchanged() -> Result<(), Box<dyn Error>> {
        let signing_key = generate_signing_key()?;
        let verifier = AdminRequestVerifier::from_certificate_file(&signing_key.certificate)
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        let public_key = verifier.public_key_bytes();
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");

        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        state.apply_registry_snapshot(
            "integration-staging",
            5,
            &[RegistrySnapshotKey {
                id: "key_0123456789abcdef0123456789abcdef".to_owned(),
                name: "example".to_owned(),
                owner: "unknown".to_owned(),
                prefix: "ci_abcdefgh".to_owned(),
                key_hash: key_hash.clone(),
                pepper_fingerprint: fingerprint.clone(),
                tags: vec![],
                rate_limit: None,
                created_at: "2026-09-18T09:00:00Z".to_owned(),
                created_by: "operator@confidential.ai".to_owned(),
                revoked_at: None,
                revoked_by: None,
                version: 1,
            }],
        )?;

        let body = snapshot_body("integration-staging", 5, &key_hash, &fingerprint);
        let body_hash = hex::encode(Sha256::digest(&body));
        let canonical = canonical_snapshot_string("integration-staging", 5, &body_hash);
        let signature = sign(&signing_key, canonical.as_bytes())?;
        let url = one_shot_server(ok_response(&body, 5, &signature));
        let poller = poller(url, public_key, state.clone());
        assert_eq!(poller.poll_once().await, Err("stale_revision"));
        assert_eq!(state.registry_cached_revision()?, Some(5));
        Ok(())
    }

    #[tokio::test]
    async fn a_304_leaves_the_cache_unchanged_and_costs_no_write() -> Result<(), Box<dyn Error>> {
        let signing_key = generate_signing_key()?;
        let verifier = AdminRequestVerifier::from_certificate_file(&signing_key.certificate)
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        let public_key = verifier.public_key_bytes();
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");

        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        state.apply_registry_snapshot(
            "integration-staging",
            3,
            &[RegistrySnapshotKey {
                id: "key_0123456789abcdef0123456789abcdef".to_owned(),
                name: "example".to_owned(),
                owner: "unknown".to_owned(),
                prefix: "ci_abcdefgh".to_owned(),
                key_hash,
                pepper_fingerprint: fingerprint,
                tags: vec![],
                rate_limit: None,
                created_at: "2026-09-18T09:00:00Z".to_owned(),
                created_by: "operator@confidential.ai".to_owned(),
                revoked_at: None,
                revoked_by: None,
                version: 1,
            }],
        )?;
        let url = one_shot_server(not_modified_response(3));
        let poller = poller(url, public_key, state.clone());
        assert!(matches!(
            poller.poll_once().await,
            Ok(PollOutcome::NotModified)
        ));
        assert_eq!(state.registry_cached_revision()?, Some(3));
        Ok(())
    }

    #[tokio::test]
    async fn a_wrong_pepper_fingerprint_row_is_skipped_and_counted() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        let outcome = state.apply_registry_snapshot(
            "integration-staging",
            1,
            &[RegistrySnapshotKey {
                id: "key_0123456789abcdef0123456789abcdef".to_owned(),
                name: "example".to_owned(),
                owner: "unknown".to_owned(),
                prefix: "ci_abcdefgh".to_owned(),
                key_hash: URL_SAFE_NO_PAD.encode([0_u8; 32]),
                pepper_fingerprint: "0".repeat(64),
                tags: vec![],
                rate_limit: None,
                created_at: "2026-09-18T09:00:00Z".to_owned(),
                created_by: "operator@confidential.ai".to_owned(),
                revoked_at: None,
                revoked_by: None,
                version: 1,
            }],
        )?;
        assert_eq!(outcome.accepted, 0);
        assert_eq!(outcome.skipped_pepper_mismatch, 1);
        assert_eq!(state.registry_cached_revision()?, Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn an_unreachable_registry_leaves_the_cache_unchanged() -> Result<(), Box<dyn Error>> {
        let signing_key = generate_signing_key()?;
        let verifier = AdminRequestVerifier::from_certificate_file(&signing_key.certificate)
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        let public_key = verifier.public_key_bytes();
        let pepper = gateway_pepper();
        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        // Nothing listens on this port.
        let poller = poller("http://127.0.0.1:1".to_owned(), public_key, state.clone());
        assert_eq!(poller.poll_once().await, Err("fetch_error"));
        assert_eq!(state.registry_cached_revision()?, None);
        Ok(())
    }

    #[tokio::test]
    async fn a_restart_with_a_cached_snapshot_still_accepts_a_cached_key_when_unreachable()
    -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let database_path = tempfile::NamedTempFile::new()?.path().to_path_buf();
        {
            let state = GatewayState::open(&database_path, pepper.clone())
                .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
                .with_mode(KeyRegistryMode::Registry);
            state.apply_registry_snapshot(
                "integration-staging",
                1,
                &[RegistrySnapshotKey {
                    id: "key_0123456789abcdef0123456789abcdef".to_owned(),
                    name: "example".to_owned(),
                    owner: "unknown".to_owned(),
                    prefix: "ci_abcdefgh".to_owned(),
                    key_hash,
                    pepper_fingerprint: fingerprint,
                    tags: vec![],
                    rate_limit: None,
                    created_at: "2026-09-18T09:00:00Z".to_owned(),
                    created_by: "operator@confidential.ai".to_owned(),
                    revoked_at: None,
                    revoked_by: None,
                    version: 1,
                }],
            )?;
        }
        // Simulate a restart: reopen the same database file.
        let restarted = GatewayState::open(&database_path, pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        assert_eq!(
            restarted.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );
        Ok(())
    }

    #[test]
    fn a_cold_start_with_no_cache_reports_not_ready() -> Result<(), Box<dyn Error>> {
        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), gateway_pepper())
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        assert!(!state.registry_ready());
        assert_eq!(state.verify("anything"), None);
        Ok(())
    }

    #[tokio::test]
    async fn dual_mode_accepts_a_local_key_and_a_registry_key() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let registry_key_hash = plaintext_key_hash(&pepper, "ci_registry_key");
        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Dual);
        state.apply_registry_snapshot(
            "integration-staging",
            1,
            &[RegistrySnapshotKey {
                id: "key_registry".to_owned(),
                name: "registry key".to_owned(),
                owner: "unknown".to_owned(),
                prefix: "ci_regist".to_owned(),
                key_hash: registry_key_hash,
                pepper_fingerprint: fingerprint,
                tags: vec![],
                rate_limit: None,
                created_at: "2026-09-18T09:00:00Z".to_owned(),
                created_by: "operator@confidential.ai".to_owned(),
                revoked_at: None,
                revoked_by: None,
                version: 1,
            }],
        )?;
        assert_eq!(
            state.verify_with_source("ci_registry_key"),
            Some(("key_registry".to_owned(), "registry"))
        );

        // A key minted through the admin API is a `local` row and must still
        // verify in dual mode.
        let admin = crate::api_keys::admin_router(state.clone());
        let body = serde_json::json!({
            "name": "local key",
            "tags": [],
            "audit": {"actor": "operator", "reason": "dual-mode test"},
        });
        let response = admin
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/api-keys")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "dual-mode-create-0001")
                    .body(Body::from(serde_json::to_vec(&body)?))?,
            )
            .await?;
        assert_eq!(response.status(), http::StatusCode::CREATED);
        let bytes = axum::body::to_bytes(response.into_body(), 1_048_576).await?;
        let created: serde_json::Value = serde_json::from_slice(&bytes)?;
        let plaintext = created["apiKey"]
            .as_str()
            .ok_or("missing apiKey in response")?;
        assert_eq!(
            state
                .verify_with_source(plaintext)
                .map(|(_, source)| source),
            Some("local")
        );
        Ok(())
    }

    #[test]
    fn a_registry_revoke_rejects_the_key_on_the_next_poll() -> Result<(), Box<dyn Error>> {
        let pepper = gateway_pepper();
        let fingerprint = pepper_fingerprint_hex(&pepper);
        let key_hash = plaintext_key_hash(&pepper, "ci_example");
        let state = GatewayState::open(tempfile::NamedTempFile::new()?.path(), pepper)
            .map_err(|error| -> Box<dyn Error> { format!("{error:?}").into() })?
            .with_mode(KeyRegistryMode::Registry);
        let row = RegistrySnapshotKey {
            id: "key_0123456789abcdef0123456789abcdef".to_owned(),
            name: "example".to_owned(),
            owner: "unknown".to_owned(),
            prefix: "ci_abcdefgh".to_owned(),
            key_hash,
            pepper_fingerprint: fingerprint,
            tags: vec![],
            rate_limit: None,
            created_at: "2026-09-18T09:00:00Z".to_owned(),
            created_by: "operator@confidential.ai".to_owned(),
            revoked_at: None,
            revoked_by: None,
            version: 1,
        };
        state.apply_registry_snapshot("integration-staging", 1, std::slice::from_ref(&row))?;
        assert_eq!(
            state.verify("ci_example"),
            Some("key_0123456789abcdef0123456789abcdef".to_owned())
        );

        let mut revoked = row;
        revoked.revoked_at = Some("2026-09-18T10:00:00Z".to_owned());
        revoked.revoked_by = Some("operator@confidential.ai".to_owned());
        revoked.version = 2;
        state.apply_registry_snapshot("integration-staging", 2, &[revoked])?;
        assert_eq!(state.verify("ci_example"), None);
        Ok(())
    }

    #[test]
    fn accepts_revision_requires_a_strictly_higher_value() {
        assert!(accepts_revision(None, 1));
        assert!(accepts_revision(Some(1), 2));
        assert!(!accepts_revision(Some(2), 2));
        assert!(!accepts_revision(Some(3), 2));
    }
}
