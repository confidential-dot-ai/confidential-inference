//! Canonical API-key state.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ApiKeyVerifier, GatewayAvailability,
    key_registry::{KeyRegistryMode, RegistrySnapshotKey},
};

type HmacSha256 = Hmac<Sha256>;
const KEY_BYTES: usize = 32;
const IDEMPOTENCY_MIN: usize = 16;
const IDEMPOTENCY_MAX: usize = 128;
const STATE_MARKER_SCHEMA: &str = "confidential.ai/gateway-state-volume/v1";
const STATE_MARKER_NAME: &str = ".confidential-inference-volume.json";
#[cfg(test)]
const STATE_DISK_SERIAL: &str = "confai-gateway-state";
const EXPORT_SCHEMA: &str = "confidential.ai/gateway-api-key-export/v1";
const PEPPER_FINGERPRINT_CONTEXT: &[u8] = b"confidential.ai/gateway-pepper-fingerprint/v1";
const FREEZE_SECONDS: i64 = 600;
const MAX_IMPORT_KEYS: usize = 10_000;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("the gateway state database failed")]
    Database(#[from] rusqlite::Error),
    #[error("the gateway state lock failed")]
    Lock,
    #[error("the gateway state input is invalid")]
    Invalid,
    #[error("the idempotency key conflicts with another request")]
    IdempotencyConflict,
    #[error("the resource version conflicts")]
    VersionConflict,
    #[error("the resource does not exist")]
    NotFound,
    #[error("secure random generation failed")]
    Random,
    #[error("the gateway state mount is invalid")]
    Mount,
    #[error("the gateway state failed its integrity check")]
    Corrupt,
    #[error("the gateway state durability operation failed")]
    Durability,
    #[error("the gateway state is unavailable")]
    Unavailable,
    #[error("the gateway state is frozen")]
    Frozen,
    #[error("the import pepper fingerprint does not match")]
    PepperMismatch,
    #[error("the import conflicts with an existing record")]
    ImportConflict,
}

#[derive(Clone)]
pub struct GatewayState {
    database: Arc<Mutex<Connection>>,
    pepper: Arc<Vec<u8>>,
    availability: GatewayAvailability,
    database_path: Option<Arc<PathBuf>>,
    mode: KeyRegistryMode,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateVolumeMarker {
    schema_version: String,
    environment: String,
    serial: String,
    filesystem_type: String,
    filesystem_uuid: String,
    #[serde(default)]
    target_migration: Option<String>,
}

fn verify_state_volume(
    directory: &Path,
    environment: &str,
    disk_serial: &str,
    mountinfo_path: &Path,
) -> Result<(), StateError> {
    let directory_metadata = fs::symlink_metadata(directory).map_err(|_| {
        tracing::warn!(path = %directory.display(), "gateway state directory metadata is unavailable");
        StateError::Mount
    })?;
    if !directory_metadata.file_type().is_dir() {
        tracing::warn!(path = %directory.display(), "gateway state path is not a directory");
        return Err(StateError::Mount);
    }
    let marker_path = directory.join(STATE_MARKER_NAME);
    let marker_metadata = fs::symlink_metadata(&marker_path).map_err(|_| StateError::Mount)?;
    if !marker_metadata.file_type().is_file()
        || (!cfg!(test) && marker_metadata.uid() != 0)
        || marker_metadata.len() == 0
        || marker_metadata.len() > 4_096
        || marker_metadata.mode() & 0o022 != 0
    {
        tracing::warn!(
            path = %marker_path.display(),
            uid = marker_metadata.uid(),
            mode = format_args!("{:o}", marker_metadata.mode() & 0o7777),
            size = marker_metadata.len(),
            "gateway state marker metadata is invalid"
        );
        return Err(StateError::Mount);
    }
    let marker_length = usize::try_from(marker_metadata.len()).map_err(|_| StateError::Mount)?;
    let mut marker_bytes = Vec::with_capacity(marker_length);
    File::open(&marker_path)
        .map_err(|_| StateError::Mount)?
        .take(4_097)
        .read_to_end(&mut marker_bytes)
        .map_err(|_| StateError::Mount)?;
    let marker: StateVolumeMarker = serde_json::from_slice(&marker_bytes).map_err(|_| {
        tracing::warn!(path = %marker_path.display(), "gateway state marker JSON is invalid");
        StateError::Mount
    })?;
    if marker.schema_version != STATE_MARKER_SCHEMA
        || marker.environment != environment
        || marker.serial != disk_serial
        || marker.filesystem_type != "ext4"
        || Uuid::parse_str(&marker.filesystem_uuid).is_err()
        || marker.target_migration.as_deref().is_some_and(|value| {
            value != "none" && value != "removed-unmounted-matching-block-device-node"
        })
    {
        tracing::warn!(
            schema = %marker.schema_version,
            environment = %marker.environment,
            serial = %marker.serial,
            filesystem = %marker.filesystem_type,
            target_migration = ?marker.target_migration,
            "gateway state marker fields are invalid"
        );
        return Err(StateError::Mount);
    }
    verify_mountinfo(directory, mountinfo_path)
}

fn verify_mountinfo(directory: &Path, mountinfo_path: &Path) -> Result<(), StateError> {
    let expected = directory.to_str().ok_or(StateError::Mount)?;
    let contents = fs::read_to_string(mountinfo_path).map_err(|_| StateError::Mount)?;
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        let Some(separator) = fields.iter().position(|value| *value == "-") else {
            continue;
        };
        if fields.get(4) != Some(&expected) || fields.get(separator + 1) != Some(&"ext4") {
            continue;
        }
        let mount_options = fields.get(5).ok_or(StateError::Mount)?;
        let super_options = fields.get(separator + 3).ok_or(StateError::Mount)?;
        let options = mount_options.split(',').chain(super_options.split(','));
        if options.clone().any(|option| option == "rw")
            && !options.clone().any(|option| option == "ro")
        {
            return Ok(());
        }
        tracing::warn!(
            path = expected,
            filesystem = fields.get(separator + 1).copied().unwrap_or("absent"),
            mount_options = *mount_options,
            super_options = *super_options,
            "gateway state mount options are invalid"
        );
    }
    tracing::warn!(
        path = expected,
        "gateway state mount is absent from mountinfo"
    );
    Err(StateError::Mount)
}

fn verify_database_integrity(database: &Connection) -> Result<(), StateError> {
    let integrity: String = database.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(StateError::Corrupt);
    }
    let schema: i64 = database.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    // Version 1 predates the key registry cache (`registry_keys`,
    // `registry_metadata`). Version 2 adds those tables additively, in place,
    // and never drops or clears `api_keys`. The gateway accepts both because
    // `from_connection` migrates a version 1 database to version 2 on open.
    if schema != 1 && schema != 2 {
        return Err(StateError::Corrupt);
    }
    Ok(())
}

fn flush_database(database: &Connection, path: &Path) -> Result<(), StateError> {
    database
        .execute_batch("PRAGMA wal_checkpoint(FULL);")
        .map_err(|_| StateError::Durability)?;
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| StateError::Durability)?;
    sync_directory(path.parent().ok_or(StateError::Durability)?)
}

fn sync_directory(path: &Path) -> Result<(), StateError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StateError::Durability)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditContext {
    pub actor: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub audit: AuditContext,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiKeyMetadata {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub tags: Vec<String>,
    pub status: String,
    pub created_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    pub version: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreatedApiKey {
    api_key: String,
    metadata: ApiKeyMetadata,
    /// The gateway mints the plaintext and computes this hash with its own
    /// pepper. The admin registry stores this hash, never the plaintext.
    key_hash: String,
    pepper_fingerprint: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyList {
    items: Vec<ApiKeyMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct ListQuery {
    cursor: Option<String>,
    limit: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedApiKey {
    pub id: String,
    pub name: String,
    pub prefix: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub verifier_hash: String,
    pub created_at: String,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revoked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub revoked_by: Option<String>,
    pub version: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyExportEnvelope {
    schema_version: String,
    pepper_fingerprint: String,
    exported_at: String,
    keys: Vec<ExportedApiKey>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportApiKeysRequest {
    schema_version: String,
    pepper_fingerprint: String,
    #[serde(default)]
    exported_at: String,
    keys: Vec<ExportedApiKey>,
    audit: AuditContext,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ImportResult {
    imported: i64,
    skipped: i64,
    total: i64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FreezeStatus {
    frozen: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    until: Option<String>,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: &'static str,
}

/// The outcome of applying one accepted key registry snapshot.
#[derive(Clone, Copy, Debug, Default)]
pub struct RegistryApplyOutcome {
    pub accepted: i64,
    pub skipped_pepper_mismatch: i64,
}

/// The body of `GET /admin/v1/api-keys/source`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySourceStatus {
    mode: KeyRegistryMode,
    cached_revision: Option<i64>,
    #[serde(rename = "lastSuccessUnix")]
    last_success_unix: Option<i64>,
    pub(crate) stale_seconds: Option<i64>,
    row_count: i64,
    pepper_mismatch_count: i64,
}

fn scan_api_keys(database: &Connection, verifier: &[u8], revoked: bool) -> Option<String> {
    let query = if revoked {
        "SELECT id,verifier FROM api_keys WHERE revoked_at_unix IS NOT NULL"
    } else {
        "SELECT id,verifier FROM api_keys WHERE revoked_at_unix IS NULL"
    };
    scan_verifier_column(database, query, verifier)
}

fn scan_registry_keys(database: &Connection, verifier: &[u8], revoked: bool) -> Option<String> {
    let query = if revoked {
        "SELECT id,key_hash FROM registry_keys WHERE revoked_at_unix IS NOT NULL"
    } else {
        "SELECT id,key_hash FROM registry_keys WHERE revoked_at_unix IS NULL"
    };
    scan_verifier_column(database, query, verifier)
}

fn scan_verifier_column(database: &Connection, query: &str, verifier: &[u8]) -> Option<String> {
    let mut statement = database.prepare(query).ok()?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .ok()?;
    for (id, expected) in rows.flatten() {
        if expected.len() == verifier.len() && bool::from(expected.ct_eq(verifier)) {
            return Some(id);
        }
    }
    None
}

impl GatewayState {
    /// Open the canonical gateway state database.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid pepper or an unavailable database.
    #[cfg(test)]
    pub fn open(path: &Path, pepper: Vec<u8>) -> Result<Self, StateError> {
        if pepper.len() < KEY_BYTES {
            return Err(StateError::Invalid);
        }
        let database = Connection::open(path)?;
        Self::from_connection(database, pepper, None, true)
    }

    /// Open the persistent `SQLite` database on the mounted gateway state disk.
    ///
    /// The disk is intentionally unencrypted in v0. The host can read, replace,
    /// delete, or roll back its contents. The database never stores plaintext
    /// API keys or the API-key pepper.
    ///
    /// # Errors
    ///
    /// Returns an error when the mount, marker, pepper, or database is invalid.
    pub fn open_persistent(
        path: &Path,
        pepper: Vec<u8>,
        environment: &str,
        disk_serial: &str,
    ) -> Result<Self, StateError> {
        Self::open_persistent_with_mountinfo(
            path,
            pepper,
            environment,
            disk_serial,
            Path::new("/proc/self/mountinfo"),
        )
    }

    fn open_persistent_with_mountinfo(
        path: &Path,
        pepper: Vec<u8>,
        environment: &str,
        disk_serial: &str,
        mountinfo_path: &Path,
    ) -> Result<Self, StateError> {
        if pepper.len() < KEY_BYTES {
            return Err(StateError::Invalid);
        }
        let directory = path.parent().ok_or(StateError::Mount)?;
        verify_state_volume(directory, environment, disk_serial, mountinfo_path)?;
        if path.exists() && !path.is_file() {
            return Err(StateError::Invalid);
        }
        let created = !path.exists();
        let database = Connection::open(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|_| StateError::Durability)?;
        let state =
            Self::from_connection(database, pepper, Some(Arc::new(path.to_path_buf())), true)?;
        {
            let database = state.database.lock().map_err(|_| StateError::Lock)?;
            verify_database_integrity(&database)?;
            flush_database(&database, path)?;
        }
        if created {
            sync_directory(directory)?;
        }
        Ok(state)
    }

    /// Create an in-memory state that always returns outage responses.
    ///
    /// # Errors
    ///
    /// Returns an error when `SQLite` cannot create the in-memory state.
    pub fn outage_only() -> Result<Self, StateError> {
        let state = Self::from_connection(
            Connection::open_in_memory()?,
            vec![0_u8; KEY_BYTES],
            None,
            false,
        )?;
        Ok(state)
    }

    #[cfg(test)]
    fn in_memory(pepper: Vec<u8>) -> Result<Self, StateError> {
        Self::from_connection(Connection::open_in_memory()?, pepper, None, true)
    }

    fn from_connection(
        database: Connection,
        pepper: Vec<u8>,
        database_path: Option<Arc<PathBuf>>,
        available: bool,
    ) -> Result<Self, StateError> {
        database.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS state_metadata (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               revision INTEGER NOT NULL CHECK(revision>=0)
             );
             INSERT OR IGNORE INTO state_metadata (singleton,revision) VALUES (1,0);
             CREATE TABLE IF NOT EXISTS api_keys (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               prefix TEXT NOT NULL,
               tags_json TEXT NOT NULL,
               verifier BLOB NOT NULL,
               created_at_unix INTEGER NOT NULL,
               created_by TEXT NOT NULL,
               revoked_at_unix INTEGER,
               revoked_by TEXT,
               version INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS idempotency (
               key TEXT PRIMARY KEY,
               operation TEXT NOT NULL,
               request_sha256 BLOB NOT NULL,
               resource_id TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS audit_events (
               id TEXT PRIMARY KEY,
               operation TEXT NOT NULL,
               resource_id TEXT NOT NULL,
               actor TEXT NOT NULL,
               reason TEXT NOT NULL,
               at_unix INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS freeze_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               until_unix INTEGER NOT NULL DEFAULT 0,
               frozen_by TEXT
             );
             INSERT OR IGNORE INTO freeze_state (singleton,until_unix) VALUES (1,0);
             CREATE TABLE IF NOT EXISTS registry_keys (
               id TEXT PRIMARY KEY,
               name TEXT NOT NULL,
               owner TEXT NOT NULL,
               prefix TEXT NOT NULL,
               key_hash BLOB NOT NULL,
               pepper_fingerprint TEXT NOT NULL,
               tags_json TEXT NOT NULL,
               created_at_unix INTEGER NOT NULL,
               created_by TEXT NOT NULL,
               revoked_at_unix INTEGER,
               revoked_by TEXT,
               version INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS registry_metadata (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               environment TEXT,
               cached_revision INTEGER,
               last_success_unix INTEGER,
               pepper_mismatch_count INTEGER NOT NULL DEFAULT 0
             );
             INSERT OR IGNORE INTO registry_metadata (singleton,pepper_mismatch_count)
               VALUES (1,0);
             PRAGMA user_version=2;",
        )?;
        let state = Self {
            database: Arc::new(Mutex::new(database)),
            pepper: Arc::new(pepper),
            availability: GatewayAvailability::new(available),
            database_path,
            mode: KeyRegistryMode::Local,
        };
        Ok(state)
    }

    /// Set the key registry read mode.
    ///
    /// `local` (the default) answers verification from `api_keys` alone.
    /// `dual` checks `api_keys` first, then the registry cache. `registry`
    /// answers from the registry cache alone. The mint, list, and revoke
    /// admin routes keep working in every mode.
    #[must_use]
    pub fn with_mode(mut self, mode: KeyRegistryMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub fn mode(&self) -> KeyRegistryMode {
        self.mode
    }

    #[must_use]
    pub fn is_available(&self) -> bool {
        self.availability.is_available()
    }

    fn require_available(&self) -> Result<(), StateError> {
        if self.is_available() {
            Ok(())
        } else {
            Err(StateError::Unavailable)
        }
    }

    fn finish_mutation(&self, database: &Connection) -> Result<(), StateError> {
        let Some(path) = &self.database_path else {
            return Ok(());
        };
        if let Err(error) = flush_database(database, path) {
            return self.fail_closed(error);
        }
        Ok(())
    }

    fn fail_closed<T>(&self, error: StateError) -> Result<T, StateError> {
        self.availability.set_available(false);
        Err(error)
    }

    #[must_use]
    pub fn availability_handle(&self) -> GatewayAvailability {
        self.availability.clone()
    }

    #[must_use]
    pub fn verify(&self, value: &str) -> Option<String> {
        self.verify_with_revocation(value, false).map(|(id, _)| id)
    }

    #[must_use]
    pub fn verify_revoked(&self, value: &str) -> Option<String> {
        self.verify_with_revocation(value, true).map(|(id, _)| id)
    }

    /// Verify a bearer token and report which key source matched it.
    ///
    /// `local` mode never looks at the registry cache. `registry` mode never
    /// looks at `api_keys`. `dual` mode checks `api_keys` first, so an
    /// operator can promote a key to the registry without a coincident
    /// verification gap.
    #[must_use]
    pub fn verify_with_source(&self, value: &str) -> Option<(String, &'static str)> {
        self.verify_with_revocation(value, false)
    }

    /// Return `false` only for `registry` mode before the first successful
    /// snapshot fetch. A registry-only gateway holds no key material yet, so
    /// it must refuse every request rather than reject every key as invalid.
    #[must_use]
    pub fn registry_ready(&self) -> bool {
        if self.mode != KeyRegistryMode::Registry {
            return true;
        }
        self.registry_cached_revision().unwrap_or(None).is_some()
    }

    fn verify_with_revocation(&self, value: &str, revoked: bool) -> Option<(String, &'static str)> {
        if !self.is_available() {
            return None;
        }
        let verifier = verifier(&self.pepper, value).ok()?;
        let database = self.database.lock().ok()?;
        match self.mode {
            KeyRegistryMode::Local => {
                scan_api_keys(&database, &verifier, revoked).map(|id| (id, "local"))
            }
            KeyRegistryMode::Registry => {
                scan_registry_keys(&database, &verifier, revoked).map(|id| (id, "registry"))
            }
            KeyRegistryMode::Dual => scan_api_keys(&database, &verifier, revoked)
                .map(|id| (id, "local"))
                .or_else(|| {
                    scan_registry_keys(&database, &verifier, revoked).map(|id| (id, "registry"))
                }),
        }
    }

    /// Apply an accepted key registry snapshot in one transaction.
    ///
    /// A row whose pepper fingerprint does not match this gateway's own
    /// pepper is skipped and counted, and the rest of the snapshot is still
    /// served. The snapshot fully replaces the cached rows: the registry
    /// serves a complete list on every fetch, not a diff, so a removed or
    /// revoked row leaves accordingly.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unavailable or the transaction
    /// fails. On an error the cache is left exactly as it was.
    pub fn apply_registry_snapshot(
        &self,
        environment: &str,
        revision: i64,
        keys: &[RegistrySnapshotKey],
    ) -> Result<RegistryApplyOutcome, StateError> {
        self.require_available()?;
        let now = unix_time();
        let expected_fingerprint = pepper_fingerprint(&self.pepper);
        let mut database = self.database.lock().map_err(|_| StateError::Lock)?;
        let transaction = database.transaction()?;
        let mut accepted = 0_i64;
        let mut skipped_pepper_mismatch = 0_i64;
        transaction.execute("DELETE FROM registry_keys", [])?;
        for key in keys {
            if !bool::from(
                expected_fingerprint
                    .as_bytes()
                    .ct_eq(key.pepper_fingerprint.as_bytes()),
            ) {
                skipped_pepper_mismatch += 1;
                continue;
            }
            let key_hash = URL_SAFE_NO_PAD
                .decode(&key.key_hash)
                .map_err(|_| StateError::Invalid)?;
            let tags = serde_json::to_string(&key.tags).map_err(|_| StateError::Invalid)?;
            transaction.execute(
                "INSERT INTO registry_keys
                 (id,name,owner,prefix,key_hash,pepper_fingerprint,tags_json,
                  created_at_unix,created_by,revoked_at_unix,revoked_by,version)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![
                    key.id,
                    key.name,
                    key.owner,
                    key.prefix,
                    key_hash,
                    key.pepper_fingerprint,
                    tags,
                    parse_timestamp(&key.created_at)?,
                    key.created_by,
                    key.revoked_at.as_deref().map(parse_timestamp).transpose()?,
                    key.revoked_by,
                    key.version,
                ],
            )?;
            accepted += 1;
        }
        transaction.execute(
            "UPDATE registry_metadata
             SET environment=?1,cached_revision=?2,last_success_unix=?3,pepper_mismatch_count=?4
             WHERE singleton=1",
            params![environment, revision, now, skipped_pepper_mismatch],
        )?;
        transaction.commit()?;
        self.finish_mutation(&database)?;
        Ok(RegistryApplyOutcome {
            accepted,
            skipped_pepper_mismatch,
        })
    }

    /// Read the cached key registry snapshot revision, if any fetch has ever
    /// succeeded.
    ///
    /// # Errors
    ///
    /// Returns an error when the database lock or query fails.
    pub fn registry_cached_revision(&self) -> Result<Option<i64>, StateError> {
        let database = self.database.lock().map_err(|_| StateError::Lock)?;
        Ok(database.query_row(
            "SELECT cached_revision FROM registry_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )?)
    }

    /// Read the key registry source status for `GET /admin/v1/api-keys/source`.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unavailable.
    pub fn registry_source_status(&self) -> Result<RegistrySourceStatus, StateError> {
        self.require_available()?;
        let database = self.database.lock().map_err(|_| StateError::Lock)?;
        let (cached_revision, last_success_unix, pepper_mismatch_count): (
            Option<i64>,
            Option<i64>,
            i64,
        ) = database.query_row(
            "SELECT cached_revision,last_success_unix,pepper_mismatch_count
             FROM registry_metadata WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let row_count: i64 =
            database.query_row("SELECT COUNT(*) FROM registry_keys", [], |row| row.get(0))?;
        let stale_seconds = last_success_unix.map(|value| (unix_time() - value).max(0));
        Ok(RegistrySourceStatus {
            mode: self.mode,
            cached_revision,
            last_success_unix,
            stale_seconds,
            row_count,
            pepper_mismatch_count,
        })
    }

    fn create(
        &self,
        request: &CreateApiKeyRequest,
        idempotency_key: &str,
    ) -> Result<(bool, String, ApiKeyMetadata, String), StateError> {
        self.require_available()?;
        validate_create(request)?;
        validate_idempotency(idempotency_key)?;
        let request_hash = json_hash(request)?;
        let now = unix_time();
        let mut database = self.database.lock().map_err(|_| StateError::Lock)?;
        let transaction = database.transaction()?;
        if let Some(resource_id) = check_idempotency(
            &transaction,
            idempotency_key,
            "create-api-key",
            &request_hash,
        )? {
            let metadata = read_metadata(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok((true, String::new(), metadata, String::new()));
        }
        require_not_frozen(&transaction)?;
        let mut secret = [0_u8; KEY_BYTES];
        getrandom::fill(&mut secret).map_err(|_| StateError::Random)?;
        let plaintext = format!("ci_{}", URL_SAFE_NO_PAD.encode(secret));
        let digest = verifier(&self.pepper, &plaintext)?;
        let id = format!("key_{}", Uuid::new_v4().simple());
        let prefix = plaintext.chars().take(12).collect::<String>();
        let tags = serde_json::to_string(&request.tags).map_err(|_| StateError::Invalid)?;
        transaction.execute(
            "INSERT INTO api_keys
             (id,name,prefix,tags_json,verifier,created_at_unix,created_by,version)
             VALUES (?1,?2,?3,?4,?5,?6,?7,1)",
            params![
                id,
                request.name,
                prefix,
                tags,
                digest,
                now,
                request.audit.actor
            ],
        )?;
        write_idempotency(
            &transaction,
            idempotency_key,
            "create-api-key",
            &request_hash,
            &id,
        )?;
        write_audit(&transaction, "create-api-key", &id, &request.audit, now)?;
        increment_revision(&transaction)?;
        let metadata = read_metadata(&transaction, &id)?;
        transaction.commit()?;
        self.finish_mutation(&database)?;
        Ok((false, plaintext, metadata, URL_SAFE_NO_PAD.encode(&digest)))
    }

    fn list(&self, cursor: Option<&str>, limit: u16) -> Result<ApiKeyList, StateError> {
        self.require_available()?;
        if !(1..=200).contains(&limit) {
            return Err(StateError::Invalid);
        }
        let database = self.database.lock().map_err(|_| StateError::Lock)?;
        let mut statement = database.prepare(
            "SELECT id,name,prefix,tags_json,created_at_unix,created_by,
                    revoked_at_unix,revoked_by,version
             FROM api_keys WHERE (?1 IS NULL OR id > ?1) ORDER BY id LIMIT ?2",
        )?;
        let items = statement
            .query_map(params![cursor, i64::from(limit) + 1], row_metadata)?
            .collect::<Result<Vec<_>, _>>()?;
        let mut visible = items;
        let next_cursor = if visible.len() > usize::from(limit) {
            visible.pop();
            visible.last().map(|item| item.id.clone())
        } else {
            None
        };
        Ok(ApiKeyList {
            items: visible,
            next_cursor,
        })
    }

    fn revoke(
        &self,
        id: &str,
        request: &AuditContext,
        idempotency_key: &str,
        expected_version: i64,
    ) -> Result<(bool, ApiKeyMetadata), StateError> {
        self.require_available()?;
        validate_audit(request)?;
        validate_idempotency(idempotency_key)?;
        let request_hash = json_hash(&(id, expected_version, request))?;
        let now = unix_time();
        let mut database = self.database.lock().map_err(|_| StateError::Lock)?;
        let transaction = database.transaction()?;
        if let Some(resource_id) = check_idempotency(
            &transaction,
            idempotency_key,
            "revoke-api-key",
            &request_hash,
        )? {
            let metadata = read_metadata(&transaction, &resource_id)?;
            transaction.commit()?;
            return Ok((true, metadata));
        }
        require_not_frozen(&transaction)?;
        let current = read_metadata(&transaction, id)?;
        if current.version != expected_version {
            return Err(StateError::VersionConflict);
        }
        if current.status == "active" {
            transaction.execute(
                "UPDATE api_keys SET revoked_at_unix=?2,revoked_by=?3,version=version+1 WHERE id=?1",
                params![id, now, request.actor],
            )?;
        }
        write_idempotency(
            &transaction,
            idempotency_key,
            "revoke-api-key",
            &request_hash,
            id,
        )?;
        write_audit(&transaction, "revoke-api-key", id, request, now)?;
        increment_revision(&transaction)?;
        let metadata = read_metadata(&transaction, id)?;
        transaction.commit()?;
        self.finish_mutation(&database)?;
        Ok((false, metadata))
    }

    /// Export every key record for a blue-green key-store carry-over.
    ///
    /// The envelope never carries the pepper or a plaintext key. It carries a
    /// fingerprint of the pepper so the importing gateway can refuse a copy
    /// signed with a different pepper.
    fn export(&self) -> Result<ApiKeyExportEnvelope, StateError> {
        self.require_available()?;
        let database = self.database.lock().map_err(|_| StateError::Lock)?;
        let mut statement = database.prepare(
            "SELECT id,name,prefix,tags_json,verifier,created_at_unix,created_by,
                    revoked_at_unix,revoked_by,version
             FROM api_keys ORDER BY id",
        )?;
        let keys = statement
            .query_map([], row_export)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ApiKeyExportEnvelope {
            schema_version: EXPORT_SCHEMA.to_owned(),
            pepper_fingerprint: pepper_fingerprint(&self.pepper),
            exported_at: timestamp(unix_time()),
            keys,
        })
    }

    /// Import an export envelope, inserting records idempotently by id.
    ///
    /// The whole import runs in one transaction. An identical existing record
    /// is skipped. A conflicting existing record refuses the entire import.
    fn import(
        &self,
        request: &ImportApiKeysRequest,
        idempotency_key: &str,
    ) -> Result<(bool, ImportResult), StateError> {
        self.require_available()?;
        validate_audit(&request.audit)?;
        validate_idempotency(idempotency_key)?;
        if request.schema_version != EXPORT_SCHEMA || request.keys.len() > MAX_IMPORT_KEYS {
            return Err(StateError::Invalid);
        }
        for key in &request.keys {
            validate_export_key(key)?;
        }
        let expected_fingerprint = pepper_fingerprint(&self.pepper);
        if !bool::from(
            expected_fingerprint
                .as_bytes()
                .ct_eq(request.pepper_fingerprint.as_bytes()),
        ) {
            return Err(StateError::PepperMismatch);
        }
        let request_hash = json_hash(request)?;
        let now = unix_time();
        let mut database = self.database.lock().map_err(|_| StateError::Lock)?;
        let transaction = database.transaction()?;
        if let Some(resource_id) = check_idempotency(
            &transaction,
            idempotency_key,
            "import-api-keys",
            &request_hash,
        )? {
            let result = decode_import_result(&resource_id)?;
            transaction.commit()?;
            return Ok((true, result));
        }
        let mut imported = 0_i64;
        let mut skipped = 0_i64;
        for key in &request.keys {
            let verifier = URL_SAFE_NO_PAD
                .decode(&key.verifier_hash)
                .map_err(|_| StateError::Invalid)?;
            match read_export_row(&transaction, &key.id)? {
                None => {
                    let tags = serde_json::to_string(&key.tags).map_err(|_| StateError::Invalid)?;
                    transaction.execute(
                        "INSERT INTO api_keys
                         (id,name,prefix,tags_json,verifier,created_at_unix,created_by,
                          revoked_at_unix,revoked_by,version)
                         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                        params![
                            key.id,
                            key.name,
                            key.prefix,
                            tags,
                            verifier,
                            parse_timestamp(&key.created_at)?,
                            key.created_by,
                            key.revoked_at.as_deref().map(parse_timestamp).transpose()?,
                            key.revoked_by,
                            key.version,
                        ],
                    )?;
                    imported += 1;
                }
                Some(current) => {
                    if export_rows_match(&current, key, &verifier) {
                        skipped += 1;
                    } else {
                        return Err(StateError::ImportConflict);
                    }
                }
            }
        }
        let result = ImportResult {
            imported,
            skipped,
            total: i64::try_from(request.keys.len()).map_err(|_| StateError::Invalid)?,
        };
        write_idempotency(
            &transaction,
            idempotency_key,
            "import-api-keys",
            &request_hash,
            &encode_import_result(&result),
        )?;
        write_audit(
            &transaction,
            "import-api-keys",
            "api-keys-bulk",
            &request.audit,
            now,
        )?;
        increment_revision(&transaction)?;
        transaction.commit()?;
        self.finish_mutation(&database)?;
        Ok((false, result))
    }

    /// Refuse new mints and revocations until unfrozen or the bound expires.
    fn freeze(
        &self,
        request: &AuditContext,
        idempotency_key: &str,
    ) -> Result<(bool, FreezeStatus), StateError> {
        self.require_available()?;
        validate_audit(request)?;
        validate_idempotency(idempotency_key)?;
        let request_hash = json_hash(request)?;
        let now = unix_time();
        let mut database = self.database.lock().map_err(|_| StateError::Lock)?;
        let transaction = database.transaction()?;
        if check_idempotency(
            &transaction,
            idempotency_key,
            "freeze-api-keys",
            &request_hash,
        )?
        .is_some()
        {
            let status = read_freeze_status(&transaction)?;
            transaction.commit()?;
            return Ok((true, status));
        }
        let until = now + FREEZE_SECONDS;
        transaction.execute(
            "UPDATE freeze_state SET until_unix=?1,frozen_by=?2 WHERE singleton=1",
            params![until, request.actor],
        )?;
        write_idempotency(
            &transaction,
            idempotency_key,
            "freeze-api-keys",
            &request_hash,
            "freeze-state",
        )?;
        write_audit(
            &transaction,
            "freeze-api-keys",
            "freeze-state",
            request,
            now,
        )?;
        increment_revision(&transaction)?;
        transaction.commit()?;
        self.finish_mutation(&database)?;
        Ok((
            false,
            FreezeStatus {
                frozen: true,
                until: Some(timestamp(until)),
            },
        ))
    }

    /// Lift a freeze early.
    fn unfreeze(
        &self,
        request: &AuditContext,
        idempotency_key: &str,
    ) -> Result<(bool, FreezeStatus), StateError> {
        self.require_available()?;
        validate_audit(request)?;
        validate_idempotency(idempotency_key)?;
        let request_hash = json_hash(request)?;
        let now = unix_time();
        let mut database = self.database.lock().map_err(|_| StateError::Lock)?;
        let transaction = database.transaction()?;
        if check_idempotency(
            &transaction,
            idempotency_key,
            "unfreeze-api-keys",
            &request_hash,
        )?
        .is_some()
        {
            let status = read_freeze_status(&transaction)?;
            transaction.commit()?;
            return Ok((true, status));
        }
        transaction.execute(
            "UPDATE freeze_state SET until_unix=0,frozen_by=?1 WHERE singleton=1",
            params![request.actor],
        )?;
        write_idempotency(
            &transaction,
            idempotency_key,
            "unfreeze-api-keys",
            &request_hash,
            "freeze-state",
        )?;
        write_audit(
            &transaction,
            "unfreeze-api-keys",
            "freeze-state",
            request,
            now,
        )?;
        increment_revision(&transaction)?;
        transaction.commit()?;
        self.finish_mutation(&database)?;
        Ok((
            false,
            FreezeStatus {
                frozen: false,
                until: None,
            },
        ))
    }

    fn freeze_status(&self) -> Result<FreezeStatus, StateError> {
        self.require_available()?;
        let database = self.database.lock().map_err(|_| StateError::Lock)?;
        read_freeze_status(&database)
    }
}

impl ApiKeyVerifier for GatewayState {
    fn verify_bearer(&self, bearer: &str) -> Option<String> {
        self.verify(bearer)
    }

    fn verify_revoked_bearer(&self, bearer: &str) -> Option<String> {
        self.verify_revoked(bearer)
    }

    fn verify_bearer_with_source(&self, bearer: &str) -> Option<(String, &'static str)> {
        self.verify_with_source(bearer)
    }

    fn is_ready(&self) -> bool {
        self.registry_ready()
    }
}

pub fn admin_router(state: GatewayState) -> Router {
    Router::new()
        .route("/admin/v1/health", get(admin_health))
        .route("/admin/v1/api-keys", get(list_keys).post(create_key))
        .route("/admin/v1/api-keys/{key_id}", delete(delete_key))
        .route("/admin/v1/api-keys/{key_id}/revoke", post(revoke_key))
        .route("/admin/v1/api-keys/export", get(export_keys))
        .route("/admin/v1/api-keys/import", post(import_keys))
        .route("/admin/v1/api-keys/freeze", post(freeze_keys))
        .route("/admin/v1/api-keys/unfreeze", post(unfreeze_keys))
        .route("/admin/v1/api-keys/source", get(key_source))
        .with_state(state)
}

async fn key_source(State(state): State<GatewayState>) -> Response {
    match state.registry_source_status() {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(error) => error_response(error),
    }
}

async fn admin_health(State(state): State<GatewayState>) -> impl IntoResponse {
    let ready = state.is_available();
    let freeze = if ready {
        state.freeze_status().ok()
    } else {
        None
    };
    let frozen = freeze.as_ref().is_some_and(|status| status.frozen);
    let mut body = serde_json::json!({
        "status": if ready { "ready" } else { "outage-only" },
        "stateAuthority": "unencrypted-persistent-ext4-state-disk",
        "stateDisk": if ready { "ready" } else { "unavailable" },
        "frozen": frozen
    });
    if let Some(until) = freeze.and_then(|status| status.until) {
        body["frozenUntil"] = serde_json::Value::String(until);
    }
    Json(body)
}

async fn export_keys(State(state): State<GatewayState>) -> Response {
    match state.export() {
        Ok(envelope) => (StatusCode::OK, Json(envelope)).into_response(),
        Err(error) => error_response(error),
    }
}

async fn import_keys(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<ImportApiKeysRequest>,
) -> Response {
    let Some(idempotency_key) = header_text(&headers, "idempotency-key") else {
        return error_response(StateError::Invalid);
    };
    match state.import(&request, idempotency_key) {
        Ok((replayed, result)) => replayable_response(StatusCode::OK, &result, replayed),
        Err(error) => error_response(error),
    }
}

async fn freeze_keys(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<AuditContext>,
) -> Response {
    let Some(idempotency_key) = header_text(&headers, "idempotency-key") else {
        return error_response(StateError::Invalid);
    };
    match state.freeze(&request, idempotency_key) {
        Ok((replayed, status)) => replayable_response(StatusCode::OK, &status, replayed),
        Err(error) => error_response(error),
    }
}

async fn unfreeze_keys(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<AuditContext>,
) -> Response {
    let Some(idempotency_key) = header_text(&headers, "idempotency-key") else {
        return error_response(StateError::Invalid);
    };
    match state.unfreeze(&request, idempotency_key) {
        Ok((replayed, status)) => replayable_response(StatusCode::OK, &status, replayed),
        Err(error) => error_response(error),
    }
}

fn replayable_response<T: Serialize>(status: StatusCode, value: &T, replayed: bool) -> Response {
    let mut response = (status, Json(value)).into_response();
    if replayed {
        response
            .headers_mut()
            .insert("idempotency-replayed", HeaderValue::from_static("true"));
    }
    response
}

async fn create_key(
    State(state): State<GatewayState>,
    headers: HeaderMap,
    Json(request): Json<CreateApiKeyRequest>,
) -> Response {
    let Some(idempotency_key) = header_text(&headers, "idempotency-key") else {
        return error_response(StateError::Invalid);
    };
    match state.create(&request, idempotency_key) {
        Ok((replayed, plaintext, metadata, key_hash)) => {
            let version = metadata.version;
            if replayed {
                json_response(StatusCode::OK, &metadata, version, true)
            } else {
                json_response(
                    StatusCode::CREATED,
                    &CreatedApiKey {
                        api_key: plaintext,
                        metadata,
                        key_hash,
                        pepper_fingerprint: pepper_fingerprint(&state.pepper),
                    },
                    version,
                    false,
                )
            }
        }
        Err(error) => error_response(error),
    }
}

async fn list_keys(State(state): State<GatewayState>, Query(query): Query<ListQuery>) -> Response {
    match state.list(query.cursor.as_deref(), query.limit.unwrap_or(50)) {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => error_response(error),
    }
}

async fn revoke_key(
    State(state): State<GatewayState>,
    AxumPath(key_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<AuditContext>,
) -> Response {
    let Some(idempotency_key) = header_text(&headers, "idempotency-key") else {
        return error_response(StateError::Invalid);
    };
    let Some(version) = etag_version(&headers) else {
        return error_response(StateError::Invalid);
    };
    match state.revoke(&key_id, &request, idempotency_key, version) {
        Ok((replayed, metadata)) => {
            let version = metadata.version;
            json_response(StatusCode::OK, &metadata, version, replayed)
        }
        Err(error) => error_response(error),
    }
}

async fn delete_key(
    State(state): State<GatewayState>,
    AxumPath(key_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<AuditContext>,
) -> Response {
    let Some(idempotency_key) = header_text(&headers, "idempotency-key") else {
        return error_response(StateError::Invalid);
    };
    let Some(version) = etag_version(&headers) else {
        return error_response(StateError::Invalid);
    };
    match state.revoke(&key_id, &request, idempotency_key, version) {
        Ok((replayed, metadata)) => {
            let version = metadata.version;
            json_response(StatusCode::OK, &metadata, version, replayed)
        }
        Err(error) => error_response(error),
    }
}

fn json_response<T: Serialize>(
    status: StatusCode,
    value: &T,
    version: i64,
    replayed: bool,
) -> Response {
    let mut response = (status, Json(value)).into_response();
    if let Ok(value) = HeaderValue::from_str(&format!("\"{version}\"")) {
        response.headers_mut().insert(header::ETAG, value);
    }
    if replayed {
        response
            .headers_mut()
            .insert("idempotency-replayed", HeaderValue::from_static("true"));
    }
    response
}

#[allow(clippy::needless_pass_by_value)]
fn error_response(error: StateError) -> Response {
    let (status, code, message) = match error {
        StateError::Invalid | StateError::Random => (
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "The request is invalid.",
        ),
        StateError::IdempotencyConflict => (
            StatusCode::CONFLICT,
            "idempotency_conflict",
            "The idempotency key conflicts.",
        ),
        StateError::VersionConflict => (
            StatusCode::PRECONDITION_FAILED,
            "version_conflict",
            "The resource version conflicts.",
        ),
        StateError::NotFound => (
            StatusCode::NOT_FOUND,
            "not_found",
            "The resource does not exist.",
        ),
        StateError::Frozen => (StatusCode::LOCKED, "frozen", "The gateway state is frozen."),
        StateError::PepperMismatch => (
            StatusCode::CONFLICT,
            "pepper_mismatch",
            "The import pepper fingerprint does not match.",
        ),
        StateError::ImportConflict => (
            StatusCode::CONFLICT,
            "import_conflict",
            "The import conflicts with an existing record.",
        ),
        StateError::Database(_)
        | StateError::Lock
        | StateError::Mount
        | StateError::Corrupt
        | StateError::Durability
        | StateError::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "state_unavailable",
            "The gateway state is unavailable.",
        ),
    };
    (status, Json(ErrorBody { code, message })).into_response()
}

fn read_metadata(connection: &Transaction<'_>, id: &str) -> Result<ApiKeyMetadata, StateError> {
    connection
        .query_row(
            "SELECT id,name,prefix,tags_json,created_at_unix,created_by,
                    revoked_at_unix,revoked_by,version FROM api_keys WHERE id=?1",
            [id],
            row_metadata,
        )
        .optional()?
        .ok_or(StateError::NotFound)
}

fn row_metadata(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiKeyMetadata> {
    let revoked_at: Option<i64> = row.get(6)?;
    let tags_json: String = row.get(3)?;
    let tags = serde_json::from_str(&tags_json).unwrap_or_default();
    Ok(ApiKeyMetadata {
        id: row.get(0)?,
        name: row.get(1)?,
        prefix: row.get(2)?,
        tags,
        status: if revoked_at.is_some() {
            "revoked".to_owned()
        } else {
            "active".to_owned()
        },
        created_at: timestamp(row.get(4)?),
        created_by: row.get(5)?,
        revoked_at: revoked_at.map(timestamp),
        revoked_by: row.get(7)?,
        version: row.get(8)?,
    })
}

fn row_export(row: &rusqlite::Row<'_>) -> rusqlite::Result<ExportedApiKey> {
    let revoked_at: Option<i64> = row.get(7)?;
    let tags_json: String = row.get(3)?;
    let tags = serde_json::from_str(&tags_json).unwrap_or_default();
    let verifier: Vec<u8> = row.get(4)?;
    Ok(ExportedApiKey {
        id: row.get(0)?,
        name: row.get(1)?,
        prefix: row.get(2)?,
        tags,
        verifier_hash: URL_SAFE_NO_PAD.encode(verifier),
        created_at: timestamp(row.get(5)?),
        created_by: row.get(6)?,
        revoked_at: revoked_at.map(timestamp),
        revoked_by: row.get(8)?,
        version: row.get(9)?,
    })
}

fn read_export_row(
    connection: &Connection,
    id: &str,
) -> Result<Option<ExportedApiKey>, StateError> {
    Ok(connection
        .query_row(
            "SELECT id,name,prefix,tags_json,verifier,created_at_unix,created_by,
                    revoked_at_unix,revoked_by,version FROM api_keys WHERE id=?1",
            [id],
            row_export,
        )
        .optional()?)
}

fn export_rows_match(current: &ExportedApiKey, incoming: &ExportedApiKey, verifier: &[u8]) -> bool {
    let Ok(current_verifier) = URL_SAFE_NO_PAD.decode(&current.verifier_hash) else {
        return false;
    };
    current.id == incoming.id
        && current.name == incoming.name
        && current.prefix == incoming.prefix
        && current.tags == incoming.tags
        && current.created_at == incoming.created_at
        && current.created_by == incoming.created_by
        && current.revoked_at == incoming.revoked_at
        && current.revoked_by == incoming.revoked_by
        && current.version == incoming.version
        && current_verifier.len() == verifier.len()
        && bool::from(current_verifier.ct_eq(verifier))
}

fn validate_export_key(key: &ExportedApiKey) -> Result<(), StateError> {
    let id_ok = key.id.len() >= 8
        && key.id.len() <= 128
        && key.id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'_' | b'-'))
        });
    if !id_ok
        || key.name.trim().is_empty()
        || key.name.len() > 100
        || key.prefix.is_empty()
        || key.prefix.len() > 16
        || key.tags.len() > 16
        || key.created_by.is_empty()
        || key.created_by.len() > 200
        || key.version < 1
        || URL_SAFE_NO_PAD.decode(&key.verifier_hash).is_err()
        || (key.revoked_at.is_none() && key.revoked_by.is_some())
        || (key.revoked_at.is_some() && key.revoked_by.is_none())
    {
        return Err(StateError::Invalid);
    }
    parse_timestamp(&key.created_at)?;
    if let Some(revoked_at) = &key.revoked_at {
        parse_timestamp(revoked_at)?;
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<i64, StateError> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map(time::OffsetDateTime::unix_timestamp)
        .map_err(|_| StateError::Invalid)
}

fn pepper_fingerprint(pepper: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(PEPPER_FINGERPRINT_CONTEXT);
    hasher.update(pepper);
    hex::encode(hasher.finalize())
}

fn encode_import_result(result: &ImportResult) -> String {
    format!("{}:{}:{}", result.imported, result.skipped, result.total)
}

fn decode_import_result(value: &str) -> Result<ImportResult, StateError> {
    let mut parts = value.split(':');
    let (Some(imported), Some(skipped), Some(total), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StateError::Corrupt);
    };
    Ok(ImportResult {
        imported: imported.parse().map_err(|_| StateError::Corrupt)?,
        skipped: skipped.parse().map_err(|_| StateError::Corrupt)?,
        total: total.parse().map_err(|_| StateError::Corrupt)?,
    })
}

fn read_freeze_status(connection: &Connection) -> Result<FreezeStatus, StateError> {
    let until: i64 = connection.query_row(
        "SELECT until_unix FROM freeze_state WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if until > unix_time() {
        Ok(FreezeStatus {
            frozen: true,
            until: Some(timestamp(until)),
        })
    } else {
        Ok(FreezeStatus {
            frozen: false,
            until: None,
        })
    }
}

fn require_not_frozen(connection: &Connection) -> Result<(), StateError> {
    if read_freeze_status(connection)?.frozen {
        Err(StateError::Frozen)
    } else {
        Ok(())
    }
}

fn check_idempotency(
    transaction: &Transaction<'_>,
    key: &str,
    operation: &str,
    request_hash: &[u8],
) -> Result<Option<String>, StateError> {
    let existing = transaction
        .query_row(
            "SELECT operation,request_sha256,resource_id FROM idempotency WHERE key=?1",
            [key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?;
    match existing {
        None => Ok(None),
        Some((old_operation, old_hash, resource_id))
            if old_operation == operation && old_hash == request_hash =>
        {
            Ok(Some(resource_id))
        }
        Some(_) => Err(StateError::IdempotencyConflict),
    }
}

fn write_idempotency(
    transaction: &Transaction<'_>,
    key: &str,
    operation: &str,
    request_hash: &[u8],
    resource_id: &str,
) -> Result<(), StateError> {
    transaction.execute(
        "INSERT INTO idempotency (key,operation,request_sha256,resource_id)
         VALUES (?1,?2,?3,?4)",
        params![key, operation, request_hash, resource_id],
    )?;
    Ok(())
}

fn write_audit(
    transaction: &Transaction<'_>,
    operation: &str,
    resource_id: &str,
    audit: &AuditContext,
    now: i64,
) -> Result<(), StateError> {
    transaction.execute(
        "INSERT INTO audit_events (id,operation,resource_id,actor,reason,at_unix)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            Uuid::new_v4().simple().to_string(),
            operation,
            resource_id,
            audit.actor,
            audit.reason,
            now
        ],
    )?;
    Ok(())
}

fn increment_revision(transaction: &Transaction<'_>) -> Result<(), StateError> {
    if transaction.execute(
        "UPDATE state_metadata SET revision=revision+1 WHERE singleton=1",
        [],
    )? != 1
    {
        return Err(StateError::Corrupt);
    }
    Ok(())
}

fn validate_create(request: &CreateApiKeyRequest) -> Result<(), StateError> {
    if request.name.trim().is_empty() || request.name.len() > 100 || request.tags.len() > 16 {
        return Err(StateError::Invalid);
    }
    validate_audit(&request.audit)?;
    let mut tags = BTreeSet::new();
    for tag in &request.tags {
        if tag.is_empty()
            || tag.len() > 32
            || !tag.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'_' | b'-'))
            })
            || !tags.insert(tag)
        {
            return Err(StateError::Invalid);
        }
    }
    Ok(())
}

fn validate_audit(audit: &AuditContext) -> Result<(), StateError> {
    if audit.actor.trim().is_empty()
        || audit.actor.len() > 200
        || audit.reason.trim().is_empty()
        || audit.reason.len() > 1_000
    {
        return Err(StateError::Invalid);
    }
    Ok(())
}

fn validate_idempotency(value: &str) -> Result<(), StateError> {
    if !(IDEMPOTENCY_MIN..=IDEMPOTENCY_MAX).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(StateError::Invalid);
    }
    Ok(())
}

fn verifier(pepper: &[u8], plaintext: &str) -> Result<Vec<u8>, StateError> {
    let mut mac = HmacSha256::new_from_slice(pepper).map_err(|_| StateError::Invalid)?;
    mac.update(plaintext.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn json_hash<T: Serialize>(value: &T) -> Result<Vec<u8>, StateError> {
    let bytes = serde_json::to_vec(value).map_err(|_| StateError::Invalid)?;
    Ok(Sha256::digest(bytes).to_vec())
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn etag_version(headers: &HeaderMap) -> Option<i64> {
    header_text(headers, "if-match")?
        .strip_prefix('"')?
        .strip_suffix('"')?
        .parse()
        .ok()
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_secs()).ok())
        .unwrap_or(0)
}

fn timestamp(value: i64) -> String {
    // SQLite keeps an integer for stable ordering. The API exposes UTC time.
    time::OffsetDateTime::from_unix_timestamp(value)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn persistent_fixture(environment: &str) -> (TempDir, PathBuf, PathBuf, Vec<u8>) {
        let directory = TempDir::new().unwrap_or_else(|_| unreachable!());
        let database_path = directory.path().join("gateway.sqlite3");
        let marker = serde_json::json!({
            "schemaVersion": STATE_MARKER_SCHEMA,
            "environment": environment,
            "serial": STATE_DISK_SERIAL,
            "filesystemType": "ext4",
            "filesystemUuid": "e7f2306d-4a35-4230-84ad-26828b7b7b81",
            "targetMigration": "none"
        });
        let marker_path = directory.path().join(STATE_MARKER_NAME);
        fs::write(
            &marker_path,
            serde_json::to_vec(&marker).unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!());
        fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o444))
            .unwrap_or_else(|_| unreachable!());
        let mountinfo_path = directory.path().join("mountinfo");
        fs::write(
            &mountinfo_path,
            format!(
                "36 25 8:1 / {} rw,nodev,nosuid,noexec - ext4 /dev/sdb rw\n",
                directory.path().display()
            ),
        )
        .unwrap_or_else(|_| unreachable!());
        let pepper = vec![7; 32];
        (directory, database_path, mountinfo_path, pepper)
    }

    fn state() -> GatewayState {
        GatewayState::in_memory(vec![7; 32]).unwrap_or_else(|_| unreachable!())
    }

    fn request() -> CreateApiKeyRequest {
        CreateApiKeyRequest {
            name: "traffic key".to_owned(),
            tags: vec!["partner".to_owned()],
            audit: AuditContext {
                actor: "operator".to_owned(),
                reason: "partner access".to_owned(),
            },
        }
    }

    #[test]
    fn plaintext_appears_once_and_the_verifier_survives() {
        let state = state();
        let (replayed, plaintext, metadata, _key_hash) = state
            .create(&request(), "create-request-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(!replayed);
        assert!(!plaintext.is_empty());
        assert_eq!(state.verify(&plaintext), Some(metadata.id.clone()));
        let (replayed, second_plaintext, second_metadata, _key_hash) = state
            .create(&request(), "create-request-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(replayed);
        assert!(second_plaintext.is_empty());
        assert_eq!(metadata.id, second_metadata.id);
    }

    #[test]
    fn revoke_checks_the_version_and_disables_the_key() {
        let state = state();
        let (_, plaintext, metadata, _key_hash) = state
            .create(&request(), "create-request-0002")
            .unwrap_or_else(|_| unreachable!());
        let audit = AuditContext {
            actor: "operator".to_owned(),
            reason: "access ended".to_owned(),
        };
        assert!(matches!(
            state.revoke(&metadata.id, &audit, "revoke-request-0001", 9),
            Err(StateError::VersionConflict)
        ));
        let (_, revoked) = state
            .revoke(&metadata.id, &audit, "revoke-request-0001", 1)
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(revoked.status, "revoked");
        assert_eq!(revoked.version, 2);
        assert_eq!(state.verify(&plaintext), None);
        assert_eq!(state.verify_revoked(&plaintext), Some(metadata.id));
    }

    #[tokio::test]
    async fn delete_route_revokes_and_replays_with_audit_metadata() {
        let state = state();
        let (_, _, metadata, _key_hash) = state
            .create(&request(), "delete-create-0001")
            .unwrap_or_else(|_| unreachable!());
        let app = admin_router(state);
        let make_request = || {
            Request::builder()
                .method("DELETE")
                .uri(format!("/admin/v1/api-keys/{}", metadata.id))
                .header("content-type", "application/json")
                .header("idempotency-key", "delete-request-0001")
                .header("if-match", "\"1\"")
                .body(Body::from(
                    r#"{"actor":"operator","reason":"access ended"}"#,
                ))
                .unwrap_or_else(|_| unreachable!())
        };
        let response = app
            .clone()
            .oneshot(make_request())
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap_or_else(|_| unreachable!());
        let value: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|_| unreachable!());
        assert_eq!(value["status"], "revoked");
        assert_eq!(value["revokedBy"], "operator");

        let response = app
            .oneshot(make_request())
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("idempotency-replayed")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
    }

    #[test]
    fn conflicting_idempotency_is_rejected() {
        let state = state();
        state
            .create(&request(), "create-request-0003")
            .unwrap_or_else(|_| unreachable!());
        let mut changed = request();
        changed.name = "changed".to_owned();
        assert!(matches!(
            state.create(&changed, "create-request-0003"),
            Err(StateError::IdempotencyConflict)
        ));
    }

    #[test]
    fn durable_verifier_survives_restart() {
        let (_directory, database_path, mountinfo_path, pepper) = persistent_fixture("production");
        let state = GatewayState::open_persistent_with_mountinfo(
            &database_path,
            pepper.clone(),
            "production",
            STATE_DISK_SERIAL,
            &mountinfo_path,
        )
        .unwrap_or_else(|_| unreachable!());
        let (_, plaintext, _, _key_hash) = state
            .create(&request(), "durable-create-0001")
            .unwrap_or_else(|_| unreachable!());
        drop(state);
        let reopened = GatewayState::open_persistent_with_mountinfo(
            &database_path,
            pepper,
            "production",
            STATE_DISK_SERIAL,
            &mountinfo_path,
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(reopened.verify(&plaintext).is_some());
    }

    #[test]
    fn a_version_1_database_migrates_to_version_2_without_data_loss() {
        let (_directory, database_path, mountinfo_path, pepper) = persistent_fixture("production");
        let plaintext = "ci_pre-migration-key";
        let digest = verifier(&pepper, plaintext).unwrap_or_else(|_| unreachable!());
        {
            // Build a version-1 database by hand, the shape a gateway build
            // before this PR would have left on disk.
            let legacy = Connection::open(&database_path).unwrap_or_else(|_| unreachable!());
            legacy
                .execute_batch(
                    "PRAGMA journal_mode=WAL;
                     CREATE TABLE state_metadata (
                       singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                       revision INTEGER NOT NULL CHECK(revision>=0)
                     );
                     INSERT INTO state_metadata (singleton,revision) VALUES (1,0);
                     CREATE TABLE api_keys (
                       id TEXT PRIMARY KEY,
                       name TEXT NOT NULL,
                       prefix TEXT NOT NULL,
                       tags_json TEXT NOT NULL,
                       verifier BLOB NOT NULL,
                       created_at_unix INTEGER NOT NULL,
                       created_by TEXT NOT NULL,
                       revoked_at_unix INTEGER,
                       revoked_by TEXT,
                       version INTEGER NOT NULL
                     );
                     CREATE TABLE idempotency (
                       key TEXT PRIMARY KEY,
                       operation TEXT NOT NULL,
                       request_sha256 BLOB NOT NULL,
                       resource_id TEXT NOT NULL
                     );
                     CREATE TABLE audit_events (
                       id TEXT PRIMARY KEY,
                       operation TEXT NOT NULL,
                       resource_id TEXT NOT NULL,
                       actor TEXT NOT NULL,
                       reason TEXT NOT NULL,
                       at_unix INTEGER NOT NULL
                     );
                     CREATE TABLE freeze_state (
                       singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                       until_unix INTEGER NOT NULL DEFAULT 0,
                       frozen_by TEXT
                     );
                     INSERT INTO freeze_state (singleton,until_unix) VALUES (1,0);
                     PRAGMA user_version=1;",
                )
                .unwrap_or_else(|_| unreachable!());
            legacy
                .execute(
                    "INSERT INTO api_keys
                     (id,name,prefix,tags_json,verifier,created_at_unix,created_by,version)
                     VALUES ('key_legacy','pre-migration','ci_pre-mig','[]',?1,0,'operator',1)",
                    params![digest],
                )
                .unwrap_or_else(|_| unreachable!());
            legacy
                .execute_batch("PRAGMA wal_checkpoint(FULL);")
                .unwrap_or_else(|_| unreachable!());
        }

        let migrated = GatewayState::open_persistent_with_mountinfo(
            &database_path,
            pepper,
            "production",
            STATE_DISK_SERIAL,
            &mountinfo_path,
        )
        .unwrap_or_else(|_| unreachable!());

        // The pre-existing key still verifies: migration never dropped or
        // cleared `api_keys`.
        assert_eq!(migrated.verify(plaintext), Some("key_legacy".to_owned()));
        let status = migrated
            .registry_source_status()
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(status.row_count, 0);

        let schema: i64 = migrated
            .database
            .lock()
            .unwrap_or_else(|_| unreachable!())
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(schema, 2);
    }

    #[test]
    fn cross_environment_and_read_only_mount_fail_closed() {
        let (_directory, database_path, mountinfo_path, pepper) = persistent_fixture("production");
        assert!(
            GatewayState::open_persistent_with_mountinfo(
                &database_path,
                pepper.clone(),
                "staging",
                STATE_DISK_SERIAL,
                &mountinfo_path,
            )
            .is_err()
        );
        let unsafe_mountinfo = mountinfo_path.with_extension("unsafe");
        fs::write(
            &unsafe_mountinfo,
            fs::read_to_string(&mountinfo_path)
                .unwrap_or_else(|_| unreachable!())
                .replace(
                    "rw,nodev,nosuid,noexec - ext4 /dev/sdb rw",
                    "ro,nodev,nosuid,noexec - ext4 /dev/sdb ro",
                ),
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(
            GatewayState::open_persistent_with_mountinfo(
                &database_path,
                pepper,
                "production",
                STATE_DISK_SERIAL,
                &unsafe_mountinfo,
            )
            .is_err()
        );
    }

    #[test]
    fn state_mount_accepts_rw_reported_as_a_super_option() {
        let (_directory, database_path, mountinfo_path, pepper) = persistent_fixture("production");
        let current = fs::read_to_string(&mountinfo_path).unwrap_or_else(|_| unreachable!());
        let split_options = current.replace(
            "rw,nodev,nosuid,noexec - ext4 /dev/sdb rw",
            "relatime - ext4 /dev/sdb rw,nodev,nosuid,noexec",
        );
        fs::write(&mountinfo_path, split_options).unwrap_or_else(|_| unreachable!());
        assert!(
            GatewayState::open_persistent_with_mountinfo(
                &database_path,
                pepper,
                "production",
                STATE_DISK_SERIAL,
                &mountinfo_path,
            )
            .is_ok()
        );
    }

    #[test]
    fn an_absent_mount_marker_never_creates_a_database() {
        let directory = TempDir::new().unwrap_or_else(|_| unreachable!());
        let path = directory.path().join("gateway.sqlite3");
        assert!(
            GatewayState::open_persistent_with_mountinfo(
                &path,
                vec![7; 32],
                "production",
                STATE_DISK_SERIAL,
                &directory.path().join("mountinfo"),
            )
            .is_err()
        );
        assert!(!path.exists());
    }

    #[test]
    fn a_corrupt_database_fails_without_replacement() {
        let (_directory, database_path, mountinfo_path, pepper) = persistent_fixture("production");
        std::fs::write(&database_path, b"not a sqlite database").unwrap_or_else(|_| unreachable!());
        assert!(
            GatewayState::open_persistent_with_mountinfo(
                &database_path,
                pepper,
                "production",
                STATE_DISK_SERIAL,
                &mountinfo_path,
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(&database_path).unwrap_or_else(|_| unreachable!()),
            b"not a sqlite database"
        );
    }

    fn import_audit() -> AuditContext {
        AuditContext {
            actor: "blue-green-switch".to_owned(),
            reason: "carry the key store to the new cluster".to_owned(),
        }
    }

    fn import_request(envelope: ApiKeyExportEnvelope) -> ImportApiKeysRequest {
        ImportApiKeysRequest {
            schema_version: envelope.schema_version,
            pepper_fingerprint: envelope.pepper_fingerprint,
            exported_at: envelope.exported_at,
            keys: envelope.keys,
            audit: import_audit(),
        }
    }

    #[test]
    fn export_import_round_trips_an_empty_store() {
        let source = state();
        let envelope = source.export().unwrap_or_else(|_| unreachable!());
        assert!(envelope.keys.is_empty());
        assert_eq!(envelope.schema_version, EXPORT_SCHEMA);

        let target = state();
        let (replayed, result) = target
            .import(&import_request(envelope), "import-empty-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(!replayed);
        assert_eq!(result.imported, 0);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.total, 0);
    }

    #[test]
    fn export_import_round_trips_one_hundred_keys() {
        let source = state();
        let mut plaintexts = Vec::new();
        for index in 0..100 {
            let mut created = request();
            created.name = format!("traffic key {index}");
            let (_, plaintext, metadata, _key_hash) = source
                .create(&created, &format!("round-trip-create-{index:04}"))
                .unwrap_or_else(|_| unreachable!());
            plaintexts.push((plaintext, metadata.id));
        }

        let envelope = source.export().unwrap_or_else(|_| unreachable!());
        assert_eq!(envelope.keys.len(), 100);

        let target = state();
        let (replayed, result) = target
            .import(&import_request(envelope), "import-hundred-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(!replayed);
        assert_eq!(result.imported, 100);
        assert_eq!(result.skipped, 0);
        assert_eq!(result.total, 100);

        for (plaintext, id) in plaintexts {
            assert_eq!(target.verify(&plaintext), Some(id));
        }
    }

    #[test]
    fn a_conflicting_record_refuses_the_whole_import() {
        let source = state();
        let (_, _, metadata, _key_hash) = source
            .create(&request(), "conflict-create-0001")
            .unwrap_or_else(|_| unreachable!());
        let envelope = source.export().unwrap_or_else(|_| unreachable!());

        let target = state();
        let (_, first_result) = target
            .import(&import_request(envelope.clone()), "conflict-import-0001")
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(first_result.imported, 1);

        let mut conflicting = envelope;
        conflicting.keys[0].name = "renamed on the source".to_owned();
        assert!(matches!(
            target.import(&import_request(conflicting), "conflict-import-0002"),
            Err(StateError::ImportConflict)
        ));
        // The original record is untouched.
        let list = target.list(None, 50).unwrap_or_else(|_| unreachable!());
        assert_eq!(list.items[0].id, metadata.id);
        assert_eq!(list.items[0].name, "traffic key");
    }

    #[test]
    fn a_pepper_mismatch_refuses_the_import() {
        let source = state();
        source
            .create(&request(), "pepper-create-0001")
            .unwrap_or_else(|_| unreachable!());
        let envelope = source.export().unwrap_or_else(|_| unreachable!());

        let target = GatewayState::in_memory(vec![9; 32]).unwrap_or_else(|_| unreachable!());
        assert!(matches!(
            target.import(&import_request(envelope), "pepper-import-0001"),
            Err(StateError::PepperMismatch)
        ));
    }

    #[test]
    fn a_freeze_refuses_a_mint_and_a_revoke() {
        let state = state();
        let (_, _, metadata, _key_hash) = state
            .create(&request(), "freeze-create-0001")
            .unwrap_or_else(|_| unreachable!());
        let (replayed, status) = state
            .freeze(&import_audit(), "freeze-request-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(!replayed);
        assert!(status.frozen);

        assert!(matches!(
            state.create(&request(), "freeze-create-0002"),
            Err(StateError::Frozen)
        ));
        assert!(matches!(
            state.revoke(&metadata.id, &import_audit(), "freeze-revoke-0001", 1),
            Err(StateError::Frozen)
        ));

        let (replayed, status) = state
            .unfreeze(&import_audit(), "unfreeze-request-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(!replayed);
        assert!(!status.frozen);
        state
            .create(&request(), "freeze-create-0003")
            .unwrap_or_else(|_| unreachable!());
    }

    #[test]
    fn a_repeated_import_replays_the_stored_counts() {
        let source = state();
        for index in 0..3 {
            let mut created = request();
            created.name = format!("traffic key {index}");
            source
                .create(&created, &format!("replay-create-{index:04}"))
                .unwrap_or_else(|_| unreachable!());
        }
        let envelope = source.export().unwrap_or_else(|_| unreachable!());

        let target = state();
        let request_body = import_request(envelope);
        let (replayed_first, first) = target
            .import(&request_body, "replay-import-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(!replayed_first);
        assert_eq!(first.imported, 3);

        let (replayed_second, second) = target
            .import(&request_body, "replay-import-0001")
            .unwrap_or_else(|_| unreachable!());
        assert!(replayed_second);
        assert_eq!(second.imported, first.imported);
        assert_eq!(second.skipped, first.skipped);
        assert_eq!(second.total, first.total);

        // Re-importing the identical content under a new idempotency key skips
        // every record instead of inserting duplicates.
        let (_, third) = target
            .import(&request_body, "replay-import-0002")
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(third.imported, 0);
        assert_eq!(third.skipped, 3);
    }

    #[tokio::test]
    async fn export_and_import_routes_round_trip_through_http() {
        let source = state();
        source
            .create(&request(), "http-create-0001")
            .unwrap_or_else(|_| unreachable!());
        let source_app = admin_router(source);
        let export_response = source_app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/admin/v1/api-keys/export")
                    .body(Body::empty())
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(export_response.status(), StatusCode::OK);
        let export_body = axum::body::to_bytes(export_response.into_body(), 1_048_576)
            .await
            .unwrap_or_else(|_| unreachable!());

        let target = state();
        let target_app = admin_router(target);
        let mut import_body: serde_json::Value =
            serde_json::from_slice(&export_body).unwrap_or_else(|_| unreachable!());
        import_body["audit"] = serde_json::json!({
            "actor": "blue-green-switch",
            "reason": "carry the key store to the new cluster"
        });
        let import_response = target_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/api-keys/import")
                    .header("content-type", "application/json")
                    .header("idempotency-key", "http-import-0001")
                    .body(Body::from(
                        serde_json::to_vec(&import_body).unwrap_or_else(|_| unreachable!()),
                    ))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(import_response.status(), StatusCode::OK);
        let import_result: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(import_response.into_body(), 4096)
                .await
                .unwrap_or_else(|_| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(import_result["imported"], 1);
    }
}
