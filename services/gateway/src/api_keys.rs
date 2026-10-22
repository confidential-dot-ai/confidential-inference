//! The gateway's API keys: an in-memory copy of the admin key registry.
//!
//! The admin registry is the only key store. The gateway holds the latest
//! snapshot in memory and never writes key material to disk. It gets the
//! snapshot in two ways (`crate::admin_client`): it pulls it from the admin
//! at startup and every 30 s, and the admin may push it through
//! `PUT /admin/v1/api-keys/snapshot` as a fast path. Both go through
//! [`KeyStore::apply`], so both follow the same contract and revision rule
//! (`crate::key_registry`).
//!
//! A restarted gateway holds no keys until the first snapshot: it is not
//! ready, and inference answers 503 `key_registry_not_ready`.

use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, put},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::{
    ApiKeyVerifier,
    key_registry::{
        RevisionDecision, SnapshotError, SnapshotPush, SnapshotPushResult, revision_decision,
        validate_push,
    },
    metrics::GatewayMetrics,
};

type HmacSha256 = Hmac<Sha256>;
const MINIMUM_PEPPER_BYTES: usize = 32;
const PEPPER_FINGERPRINT_CONTEXT: &[u8] = b"confidential.ai/gateway-pepper-fingerprint/v1";
/// How many characters of a pepper fingerprint an error detail prints.
const FINGERPRINT_PREFIX_CHARACTERS: usize = 12;

struct CachedKey {
    id: String,
    hash: Vec<u8>,
    revoked: bool,
}

struct Snapshot {
    revision: i64,
    applied_at_unix: i64,
    keys: Vec<CachedKey>,
    pepper_mismatch_count: i64,
}

/// The key snapshot this gateway serves from.
pub struct KeyStore {
    pepper: Vec<u8>,
    pepper_fingerprint: String,
    environment: String,
    metrics: Option<Arc<GatewayMetrics>>,
    snapshot: RwLock<Option<Snapshot>>,
    created: Instant,
}

/// How long `/ready` waits for the first snapshot before it passes without
/// one. Under the c8s per-pod mesh (c8s >= v0.64) a gateway pod has no egress
/// to the admin until C8s#1047 adds declared egress, so the pull fails and
/// only the admin's push can bring keys. The admin reaches gateway pods
/// through the headless `c8s-gateway` Service, which lists ready pods only:
/// a readiness gate without this limit would never let a push reach a new
/// pod. After the limit the pod is Ready, inference answers 503
/// `key_registry_not_ready` until a push or pull lands, and the next admin
/// repair pass (every 30 s) pushes the keys. When the pull works, keys arrive
/// within seconds and the limit never applies.
pub const KEYLESS_READY_AFTER: Duration = Duration::from_secs(60);

/// The body of `GET /admin/v1/api-keys/source`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceStatus {
    cached_revision: Option<i64>,
    #[serde(rename = "lastSuccessUnix")]
    last_success_unix: Option<i64>,
    stale_seconds: Option<i64>,
    row_count: usize,
    pepper_mismatch_count: i64,
    /// The fingerprint of the pepper this gateway holds. The admin compares
    /// it with the snapshot it would serve, so a pepper change shows up as
    /// drift.
    pepper_fingerprint: String,
}

impl KeyStore {
    /// Create an empty store for one environment. An empty environment
    /// accepts a snapshot of any environment (unit tests only).
    ///
    /// # Errors
    ///
    /// Returns `SnapshotError::Invalid` for a pepper shorter than 32 bytes.
    pub fn new(pepper: Vec<u8>, environment: &str) -> Result<Self, SnapshotError> {
        if pepper.len() < MINIMUM_PEPPER_BYTES {
            return Err(SnapshotError::Invalid);
        }
        Ok(Self {
            pepper_fingerprint: pepper_fingerprint(&pepper),
            pepper,
            environment: environment.to_owned(),
            metrics: None,
            snapshot: RwLock::new(None),
            created: Instant::now(),
        })
    }

    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<GatewayMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// The revision this gateway holds, if any snapshot was applied.
    #[must_use]
    pub fn cached_revision(&self) -> Option<i64> {
        self.read().as_ref().map(|snapshot| snapshot.revision)
    }

    /// Seconds since the last applied or acknowledged snapshot.
    #[must_use]
    pub fn stale_seconds(&self) -> Option<i64> {
        self.read()
            .as_ref()
            .map(|snapshot| (unix_time() - snapshot.applied_at_unix).max(0))
    }

    /// Apply one snapshot, pulled or pushed, after the contract check, the
    /// pepper check and the revision rule.
    ///
    /// A strictly higher revision replaces the whole cache. The revision
    /// the gateway already holds is an acknowledgement and changes nothing.
    /// A lower revision is refused.
    ///
    /// # Errors
    ///
    /// Returns the reason for a refused snapshot. The cache is unchanged.
    pub fn apply(&self, push: &SnapshotPush) -> Result<SnapshotPushResult, SnapshotError> {
        let result = self.apply_inner(push);
        if let Some(metrics) = &self.metrics {
            match &result {
                Ok(_) => {
                    metrics.set_key_registry_revision(push.revision);
                    metrics.set_key_registry_stale_seconds(0.0);
                }
                Err(error) => metrics.record_key_registry_push_rejection(error.code()),
            }
        }
        result
    }

    fn apply_inner(&self, push: &SnapshotPush) -> Result<SnapshotPushResult, SnapshotError> {
        validate_push(push, &self.environment)?;
        self.check_snapshot_pepper(push)?;
        let mut guard = self
            .snapshot
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cached = guard.as_ref().map(|snapshot| snapshot.revision);
        match revision_decision(cached, push.revision) {
            RevisionDecision::Refuse => Err(SnapshotError::StaleRevision),
            RevisionDecision::AlreadyHeld => {
                if let Some(snapshot) = guard.as_mut() {
                    snapshot.applied_at_unix = unix_time();
                }
                Ok(SnapshotPushResult {
                    revision: push.revision,
                    cached_revision: push.revision,
                    accepted: 0,
                    skipped_pepper_mismatch: 0,
                    applied: false,
                })
            }
            RevisionDecision::Apply => {
                let snapshot = self.parse(push)?;
                let accepted = i64::try_from(snapshot.keys.len()).unwrap_or(i64::MAX);
                let skipped = snapshot.pepper_mismatch_count;
                if let Some(metrics) = &self.metrics {
                    metrics
                        .set_key_registry_pepper_mismatch_rows(u64::try_from(skipped).unwrap_or(0));
                }
                *guard = Some(snapshot);
                tracing::info!(
                    revision = push.revision,
                    accepted,
                    skipped_pepper_mismatch = skipped,
                    "applied a key registry snapshot"
                );
                Ok(SnapshotPushResult {
                    revision: push.revision,
                    cached_revision: push.revision,
                    accepted,
                    skipped_pepper_mismatch: skipped,
                    applied: true,
                })
            }
        }
    }

    /// Parse every row before anything is replaced, so one bad row refuses
    /// the whole snapshot. A row that names another pepper is skipped and
    /// counted: a rotation can leave one old row behind.
    fn parse(&self, push: &SnapshotPush) -> Result<Snapshot, SnapshotError> {
        let mut keys = Vec::with_capacity(push.keys.len());
        let mut pepper_mismatch_count = 0;
        for key in &push.keys {
            parse_timestamp(&key.created_at)?;
            if let Some(revoked_at) = &key.revoked_at {
                parse_timestamp(revoked_at)?;
            }
            let hash = URL_SAFE_NO_PAD
                .decode(&key.key_hash)
                .map_err(|_| SnapshotError::Invalid)?;
            if !bool::from(
                self.pepper_fingerprint
                    .as_bytes()
                    .ct_eq(key.pepper_fingerprint.as_bytes()),
            ) {
                pepper_mismatch_count += 1;
                continue;
            }
            keys.push(CachedKey {
                id: key.id.clone(),
                hash,
                revoked: key.revoked_at.is_some(),
            });
        }
        Ok(Snapshot {
            revision: push.revision,
            applied_at_unix: unix_time(),
            keys,
            pepper_mismatch_count,
        })
    }

    /// Refuse a snapshot whose envelope names another pepper: none of its
    /// rows could ever match, so applying it would replace a working cache
    /// with rows that authenticate nothing. An empty envelope fingerprint
    /// states nothing and keeps the per-row rule.
    fn check_snapshot_pepper(&self, push: &SnapshotPush) -> Result<(), SnapshotError> {
        if push.pepper_fingerprint.is_empty() {
            return Ok(());
        }
        let matches = bool::from(
            self.pepper_fingerprint
                .as_bytes()
                .ct_eq(push.pepper_fingerprint.as_bytes()),
        );
        if let Some(metrics) = &self.metrics {
            metrics.set_key_registry_pepper_mismatch(!matches);
        }
        if matches {
            return Ok(());
        }
        tracing::error!(
            expected = fingerprint_prefix(&self.pepper_fingerprint),
            received = fingerprint_prefix(&push.pepper_fingerprint),
            "refused a key registry snapshot: the pepper does not match"
        );
        Err(SnapshotError::PepperMismatch {
            expected: self.pepper_fingerprint.clone(),
            received: push.pepper_fingerprint.clone(),
        })
    }

    #[must_use]
    pub fn verify(&self, value: &str) -> Option<String> {
        self.find(value, false)
    }

    #[must_use]
    pub fn verify_revoked(&self, value: &str) -> Option<String> {
        self.find(value, true)
    }

    fn find(&self, value: &str, revoked: bool) -> Option<String> {
        let mut mac = HmacSha256::new_from_slice(&self.pepper).ok()?;
        mac.update(value.as_bytes());
        let hash = mac.finalize().into_bytes();
        let guard = self.read();
        guard.as_ref()?.keys.iter().find_map(|key| {
            (key.revoked == revoked
                && key.hash.len() == hash.len()
                && bool::from(key.hash.ct_eq(&hash)))
            .then(|| key.id.clone())
        })
    }

    #[must_use]
    pub fn source_status(&self) -> SourceStatus {
        let guard = self.read();
        let snapshot = guard.as_ref();
        SourceStatus {
            cached_revision: snapshot.map(|snapshot| snapshot.revision),
            last_success_unix: snapshot.map(|snapshot| snapshot.applied_at_unix),
            stale_seconds: snapshot.map(|snapshot| (unix_time() - snapshot.applied_at_unix).max(0)),
            row_count: snapshot.map_or(0, |snapshot| snapshot.keys.len()),
            pepper_mismatch_count: snapshot.map_or(0, |snapshot| snapshot.pepper_mismatch_count),
            pepper_fingerprint: self.pepper_fingerprint.clone(),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Option<Snapshot>> {
        self.snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ApiKeyVerifier for KeyStore {
    fn verify_bearer(&self, bearer: &str) -> Option<String> {
        self.verify(bearer)
    }

    fn verify_revoked_bearer(&self, bearer: &str) -> Option<String> {
        self.verify_revoked(bearer)
    }

    fn is_ready(&self) -> bool {
        self.cached_revision().is_some()
    }

    fn passes_readiness(&self) -> bool {
        self.is_ready() || self.created.elapsed() >= KEYLESS_READY_AFTER
    }
}

/// The admin routes of the key store. They must be wrapped in the gateway's
/// admin request check (`crate::admin_auth`).
pub fn admin_router(store: Arc<KeyStore>) -> Router {
    Router::new()
        .route("/admin/v1/health", get(admin_health))
        .route("/admin/v1/api-keys/source", get(key_source))
        .route("/admin/v1/api-keys/snapshot", put(push_snapshot))
        .with_state(store)
}

async fn push_snapshot(
    State(store): State<Arc<KeyStore>>,
    Json(push): Json<SnapshotPush>,
) -> Response {
    match store.apply(&push) {
        Ok(result) => (StatusCode::OK, Json(result)).into_response(),
        Err(error) => error_response(&error),
    }
}

async fn key_source(State(store): State<Arc<KeyStore>>) -> Response {
    (StatusCode::OK, Json(store.source_status())).into_response()
}

async fn admin_health(State(store): State<Arc<KeyStore>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": if store.is_ready() { "ready" } else { "key_registry_not_ready" },
        "cachedRevision": store.cached_revision(),
    }))
}

fn error_response(error: &SnapshotError) -> Response {
    let (status, message, detail) = match error {
        SnapshotError::Invalid => (StatusCode::BAD_REQUEST, "The request is invalid.", None),
        SnapshotError::StaleRevision => (
            StatusCode::CONFLICT,
            "The pushed snapshot revision is lower than the cached revision.",
            None,
        ),
        SnapshotError::PepperMismatch { expected, received } => (
            StatusCode::CONFLICT,
            "The pushed snapshot names a different pepper than the gateway holds.",
            Some(format!(
                "the gateway holds pepper {}, the snapshot names pepper {}",
                fingerprint_prefix(expected),
                fingerprint_prefix(received),
            )),
        ),
    };
    let mut body = serde_json::json!({"code": error.code(), "message": message});
    if let Some(detail) = detail {
        body["detail"] = serde_json::Value::String(detail);
    }
    (status, Json(body)).into_response()
}

/// The first 12 characters of a pepper fingerprint: enough to tell two
/// peppers apart in a log line, and the length the operator tools print.
fn fingerprint_prefix(fingerprint: &str) -> &str {
    let end = fingerprint
        .char_indices()
        .nth(FINGERPRINT_PREFIX_CHARACTERS)
        .map_or(fingerprint.len(), |(index, _)| index);
    &fingerprint[..end]
}

fn parse_timestamp(value: &str) -> Result<i64, SnapshotError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(time::OffsetDateTime::unix_timestamp)
        .map_err(|_| SnapshotError::Invalid)
}

fn pepper_fingerprint(pepper: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PEPPER_FINGERPRINT_CONTEXT);
    hasher.update(pepper);
    hex::encode(hasher.finalize())
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}
