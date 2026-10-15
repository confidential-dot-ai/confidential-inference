//! Bounded, content-free minute aggregates and durable snapshot delivery.
//!
//! Only committed snapshots leave this module. Request bodies and credentials
//! are never part of a bucket. Unflushed observations can be lost on a crash.

use futures_util::StreamExt;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_BATCH_RECORDS: usize = 256;
pub const MAX_BATCH_BYTES: usize = 262_144;
const MAX_COUNTER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub environment: String,
    pub cluster_id: String,
    pub key_realm: String,
    pub producer_id: String,
    pub endpoint: String,
    pub token: String,
    #[serde(default)]
    pub tls_identity_pem: Option<String>,
    #[serde(default)]
    pub tls_ca_pem: Option<String>,
    #[serde(default)]
    pub connect_address: Option<std::net::IpAddr>,
    pub models: BTreeMap<String, Model>,
    pub max_buckets: usize,
    pub max_database_bytes: u64,
    pub acknowledged_retention_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub served_model: String,
    pub model_revision: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub requests: u64,
    pub completed: u64,
    pub failed: u64,
    pub cancelled: u64,
    pub interrupted: u64,
    pub complete_usage: u64,
    pub partial_usage: u64,
    pub unavailable_usage: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cached_input_tokens: u64,
    pub reasoning_tokens: u64,
    pub input_known: u64,
    pub output_known: u64,
    pub cache_known: u64,
    pub reasoning_known: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    pub bucket_id: String,
    pub producer_id: String,
    pub environment: String,
    pub cluster_id: String,
    pub key_realm: String,
    pub key_id: String,
    pub requested_model: String,
    pub served_model: String,
    pub model_revision: String,
    pub bucket_start_ms: u64,
    pub revision: u64,
    pub counts: Counts,
}

impl Bucket {
    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn identity(&self) -> Result<String, serde_json::Error> {
        let data = serde_json::to_vec(&(
            &self.producer_id,
            &self.environment,
            &self.cluster_id,
            &self.key_realm,
            &self.key_id,
            &self.requested_model,
            &self.served_model,
            &self.model_revision,
            self.bucket_start_ms,
        ))?;
        Ok(hex::encode(Sha256::digest(data)))
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Outcome {
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cached: Option<u64>,
    pub reasoning: Option<u64>,
    pub final_usage: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid usage configuration")]
    Config,
    #[error("usage capacity unavailable")]
    Capacity,
    #[error("usage state unavailable")]
    State,
    #[error("usage storage failed")]
    Database(#[from] rusqlite::Error),
    #[error("invalid usage snapshot")]
    Json(#[from] serde_json::Error),
}

#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |v| u64::try_from(v.as_millis()).unwrap_or(MAX_COUNTER))
}

#[must_use]
pub fn safe_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
}

impl Config {
    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn validate(&self) -> Result<(), Error> {
        let url = url::Url::parse(&self.endpoint).map_err(|_| Error::Config)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.token.len() < 32
            || self.token.len() > 256
            || !self
                .token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !safe_id(&self.environment, 32)
            || !safe_id(&self.cluster_id, 96)
            || !safe_id(&self.key_realm, 32)
            || !safe_id(&self.producer_id, 96)
            || self.models.is_empty()
            || self.models.len() > 64
            || self.models.iter().any(|(key, model)| {
                !safe_id(key, 128)
                    || !safe_id(&model.served_model, 128)
                    || !safe_id(&model.model_revision, 96)
            })
            || !(16..=131_072).contains(&self.max_buckets)
            || !(4_194_304..=1_073_741_824).contains(&self.max_database_bytes)
            || self.acknowledged_retention_seconds > 604_800
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}

struct Entry {
    bucket: Bucket,
    dirty: bool,
    acknowledged_at: Option<u64>,
    quarantined: bool,
}
struct State {
    database: Connection,
    entries: BTreeMap<String, Entry>,
    active: usize,
    storage_failed: bool,
    last_flush_ms: u64,
    last_delivery_ms: u64,
}

pub struct Recorder {
    config: Config,
    state: Mutex<State>,
}

#[derive(Serialize)]
pub struct Status {
    buckets: usize,
    active_requests: usize,
    pending_buckets: usize,
    quarantined_buckets: usize,
    oldest_pending_minute_ms: Option<u64>,
    last_flush_ms: u64,
    last_delivery_ms: u64,
    storage_failed: bool,
    max_buckets: usize,
    max_database_bytes: u64,
}

impl Recorder {
    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn open(path: &Path, config: Config) -> Result<Arc<Self>, Error> {
        config.validate()?;
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err(Error::Config);
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|_| Error::State)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::State)?;
        let database = Connection::open(path)?;
        database.busy_timeout(Duration::from_millis(250))?;
        // DELETE journals are bounded by changed database pages. A dedicated
        // database avoids growth or checkpoint coupling with the key registry.
        database.pragma_update(None, "journal_mode", "DELETE")?;
        database.pragma_update(None, "synchronous", "FULL")?;
        // Leave space for a rollback journal and its headers within the budget.
        let pages = config.max_database_bytes / 3 / 4096;
        let actual: i64 =
            database.query_row(&format!("PRAGMA max_page_count={pages}"), [], |r| r.get(0))?;
        if actual > i64::try_from(pages).map_err(|_| Error::Config)? {
            return Err(Error::Capacity);
        }
        database.execute_batch("CREATE TABLE IF NOT EXISTS usage_identity(binding TEXT NOT NULL); CREATE TABLE IF NOT EXISTS usage_queue(bucket_id TEXT PRIMARY KEY,payload TEXT NOT NULL,acknowledged_at INTEGER,quarantined INTEGER NOT NULL DEFAULT 0);")?;
        let binding = serde_json::to_string(&(
            &config.environment,
            &config.cluster_id,
            &config.key_realm,
            &config.producer_id,
        ))?;
        let stored: Option<String> = database
            .query_row("SELECT binding FROM usage_identity", [], |r| r.get(0))
            .ok();
        if let Some(stored) = stored {
            if stored != binding {
                return Err(Error::Config);
            }
        } else {
            database.execute("INSERT INTO usage_identity VALUES (?)", [&binding])?;
        }
        let count: i64 =
            database.query_row("SELECT count(*) FROM usage_queue", [], |r| r.get(0))?;
        if count > i64::try_from(config.max_buckets).map_err(|_| Error::Config)? {
            return Err(Error::Capacity);
        }
        let mut entries = BTreeMap::new();
        {
            let mut query =
                database.prepare("SELECT payload,acknowledged_at,quarantined FROM usage_queue")?;
            for row in query.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?
                        .and_then(|v| u64::try_from(v).ok()),
                    r.get::<_, bool>(2)?,
                ))
            })? {
                let (payload, acknowledged_at, quarantined) = row?;
                let bucket: Bucket = serde_json::from_str(&payload)?;
                if bucket.identity()? != bucket.bucket_id {
                    return Err(Error::State);
                }
                entries.insert(
                    bucket.bucket_id.clone(),
                    Entry {
                        bucket,
                        dirty: false,
                        acknowledged_at,
                        quarantined,
                    },
                );
            }
        }
        Ok(Arc::new(Self {
            config,
            state: Mutex::new(State {
                database,
                entries,
                active: 0,
                storage_failed: false,
                last_flush_ms: 0,
                last_delivery_ms: 0,
            }),
        }))
    }

    /// Return operational status without key IDs, model names, or credentials.
    #[must_use]
    pub fn status(&self) -> Option<Status> {
        let state = self.state.lock().ok()?;
        Some(Status {
            buckets: state.entries.len(),
            active_requests: state.active,
            pending_buckets: state
                .entries
                .values()
                .filter(|e| e.acknowledged_at.is_none())
                .count(),
            quarantined_buckets: state.entries.values().filter(|e| e.quarantined).count(),
            oldest_pending_minute_ms: state
                .entries
                .values()
                .filter(|e| e.acknowledged_at.is_none())
                .map(|e| e.bucket.bucket_start_ms)
                .min(),
            last_flush_ms: state.last_flush_ms,
            last_delivery_ms: state.last_delivery_ms,
            storage_failed: state.storage_failed,
            max_buckets: self.config.max_buckets,
            max_database_bytes: self.config.max_database_bytes,
        })
    }

    /// Requeue retained snapshots after an Admin database restore.
    /// # Errors
    /// Rejects an invalid recovery range or a storage failure.
    pub fn replay(&self, from_ms: u64, now: u64) -> Result<usize, Error> {
        if from_ms > now
            || now.saturating_sub(from_ms) > self.config.acknowledged_retention_seconds * 1000
        {
            return Err(Error::Config);
        }
        let mut state = self.state.lock().map_err(|_| Error::State)?;
        let ids: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, e)| {
                e.bucket.bucket_start_ms >= from_ms / 60_000 * 60_000 && !e.quarantined
            })
            .map(|(id, _)| id.clone())
            .collect();
        let transaction = state.database.transaction()?;
        for id in &ids {
            transaction.execute(
                "UPDATE usage_queue SET acknowledged_at=NULL WHERE bucket_id=? AND quarantined=0",
                [id],
            )?;
        }
        transaction.commit()?;
        for id in &ids {
            if let Some(e) = state.entries.get_mut(id) {
                e.acknowledged_at = None;
            }
        }
        Ok(ids.len())
    }

    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn reserve(
        self: &Arc<Self>,
        key_id: &str,
        requested_model: &str,
    ) -> Result<RequestUsage, Error> {
        if !safe_id(key_id, 128) {
            return Err(Error::Config);
        }
        let model = self
            .config
            .models
            .get(requested_model)
            .ok_or(Error::Config)?
            .clone();
        let mut state = self.state.lock().map_err(|_| Error::State)?;
        // Reserve one slot per active request. Even when every request finishes
        // in a different minute, final accounting remains within the row cap.
        if state.storage_failed || state.entries.len() + state.active >= self.config.max_buckets {
            return Err(Error::Capacity);
        }
        state.active += 1;
        Ok(RequestUsage {
            recorder: self.clone(),
            key_id: key_id.to_owned(),
            requested_model: requested_model.to_owned(),
            model,
            observation: Observation::default(),
            outcome: Outcome::Cancelled,
            ended_at: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        key_id: &str,
        requested_model: &str,
        model: &Model,
        observation: Observation,
        outcome: Outcome,
        ended_at: u64,
    ) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::State)?;
        state.active = state.active.saturating_sub(1);
        let mut bucket = Bucket {
            bucket_id: String::new(),
            producer_id: self.config.producer_id.clone(),
            environment: self.config.environment.clone(),
            cluster_id: self.config.cluster_id.clone(),
            key_realm: self.config.key_realm.clone(),
            key_id: key_id.to_owned(),
            requested_model: requested_model.to_owned(),
            served_model: model.served_model.clone(),
            model_revision: model.model_revision.clone(),
            bucket_start_ms: ended_at / 60_000 * 60_000,
            revision: 0,
            counts: Counts::default(),
        };
        bucket.bucket_id = bucket.identity()?;
        let entry = state
            .entries
            .entry(bucket.bucket_id.clone())
            .or_insert(Entry {
                bucket,
                dirty: false,
                acknowledged_at: None,
                quarantined: false,
            });
        let mut counts = entry.bucket.counts.clone();
        let increment = |v: &mut u64, n: u64| -> Result<(), Error> {
            *v = v
                .checked_add(n)
                .filter(|v| *v <= MAX_COUNTER)
                .ok_or(Error::Capacity)?;
            Ok(())
        };
        increment(&mut counts.requests, 1)?;
        match outcome {
            Outcome::Completed => increment(&mut counts.completed, 1)?,
            Outcome::Failed => increment(&mut counts.failed, 1)?,
            Outcome::Cancelled => increment(&mut counts.cancelled, 1)?,
            Outcome::Interrupted => increment(&mut counts.interrupted, 1)?,
        }
        if observation.final_usage && observation.input.is_some() && observation.output.is_some() {
            increment(&mut counts.complete_usage, 1)?;
        } else if observation.input.is_some() || observation.output.is_some() {
            increment(&mut counts.partial_usage, 1)?;
        } else {
            increment(&mut counts.unavailable_usage, 1)?;
        }
        for (value, total, known) in [
            (
                observation.input,
                &mut counts.input_tokens,
                &mut counts.input_known,
            ),
            (
                observation.output,
                &mut counts.output_tokens,
                &mut counts.output_known,
            ),
            (
                observation.cached,
                &mut counts.cached_input_tokens,
                &mut counts.cache_known,
            ),
            (
                observation.reasoning,
                &mut counts.reasoning_tokens,
                &mut counts.reasoning_known,
            ),
        ] {
            if let Some(n) = value {
                increment(total, n)?;
                increment(known, 1)?;
            }
        }
        entry.bucket.counts = counts;
        entry.dirty = true;
        entry.acknowledged_at = None;
        Ok(())
    }

    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn flush(&self, now: u64) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::State)?;
        let result = Self::flush_locked(&mut state, &self.config, now);
        state.storage_failed = result.is_err();
        if result.is_ok() {
            state.last_flush_ms = now;
        }
        result
    }

    fn flush_locked(state: &mut State, config: &Config, now: u64) -> Result<(), Error> {
        let expired: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, entry)| {
                !entry.dirty
                    && entry.acknowledged_at.is_some_and(|at| {
                        now.saturating_sub(at) > config.acknowledged_retention_seconds * 1000
                    })
                    && entry.bucket.bucket_start_ms + 60_000 < now
            })
            .map(|(id, _)| id.clone())
            .collect();
        let dirty: Vec<_> = state
            .entries
            .iter()
            .filter(|(_, e)| e.dirty)
            .map(|(id, e)| {
                let mut b = e.bucket.clone();
                b.revision = b
                    .revision
                    .checked_add(1)
                    .filter(|r| *r <= MAX_COUNTER)
                    .ok_or(Error::Capacity)?;
                Ok((id.clone(), serde_json::to_string(&b)?, b))
            })
            .collect::<Result<_, Error>>()?;
        if dirty.is_empty() && expired.is_empty() {
            return Ok(());
        }
        let tx = state.database.transaction()?;
        for id in &expired {
            tx.execute("DELETE FROM usage_queue WHERE bucket_id=?", [id])?;
        }
        for (id, payload, _) in &dirty {
            tx.execute("INSERT INTO usage_queue VALUES (?1,?2,NULL,0) ON CONFLICT(bucket_id) DO UPDATE SET payload=excluded.payload,acknowledged_at=NULL", params![id, payload])?;
        }
        tx.commit()?;
        for id in expired {
            state.entries.remove(&id);
        }
        for (id, _, bucket) in dirty {
            if let Some(e) = state.entries.get_mut(&id) {
                e.bucket = bucket;
                e.dirty = false;
            }
        }
        Ok(())
    }

    /// Select only durable rows. An in-memory bucket can already be newer.
    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn batch(&self) -> Result<Vec<Bucket>, Error> {
        let state = self.state.lock().map_err(|_| Error::State)?;
        let mut query = state.database.prepare("SELECT payload FROM usage_queue WHERE acknowledged_at IS NULL AND quarantined=0 ORDER BY bucket_id LIMIT 256")?;
        let mut buckets = Vec::new();
        for row in query.query_map([], |r| r.get::<_, String>(0))? {
            let bucket: Bucket = serde_json::from_str(&row?)?;
            buckets.push(bucket);
            if serde_json::to_vec(&serde_json::json!({"buckets": buckets}))?.len() > MAX_BATCH_BYTES
            {
                buckets.pop();
                break;
            }
        }
        Ok(buckets)
    }

    /// # Errors
    /// Returns an error if the input is invalid, capacity is exhausted, or storage fails.
    pub fn acknowledge(&self, bucket: &Bucket, now: u64, quarantine: bool) -> Result<(), Error> {
        self.acknowledge_batch(&[(bucket.clone(), quarantine)], now)
    }

    fn acknowledge_batch(&self, buckets: &[(Bucket, bool)], now: u64) -> Result<(), Error> {
        let mut state = self.state.lock().map_err(|_| Error::State)?;
        let transaction = state.database.transaction()?;
        let mut changed_rows = Vec::new();
        for (bucket, quarantine) in buckets {
            let payload = serde_json::to_string(bucket)?;
            let changed = if *quarantine {
                transaction.execute(
                    "UPDATE usage_queue SET quarantined=1 WHERE bucket_id=?1 AND payload=?2",
                    params![bucket.bucket_id, payload],
                )?
            } else {
                transaction.execute(
                    "UPDATE usage_queue SET acknowledged_at=?3 WHERE bucket_id=?1 AND payload=?2",
                    params![
                        bucket.bucket_id,
                        payload,
                        i64::try_from(now).map_err(|_| Error::State)?
                    ],
                )?
            };
            if changed > 0 {
                changed_rows.push((bucket, *quarantine));
            }
        }
        transaction.commit()?;
        for (bucket, quarantine) in changed_rows {
            if let Some(e) = state.entries.get_mut(&bucket.bucket_id)
                && e.bucket.revision == bucket.revision
            {
                e.quarantined = quarantine;
                if !e.dirty && !quarantine {
                    e.acknowledged_at = Some(now);
                }
            }
        }
        state.last_delivery_ms = now;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn spawn(self: &Arc<Self>) {
        let recorder = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(1));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                timer.tick().await;
                let store = recorder.clone();
                if !matches!(
                    tokio::task::spawn_blocking(move || store.flush(now_ms())).await,
                    Ok(Ok(()))
                ) {
                    tracing::error!("usage persistence failed");
                }
            }
        });
        let recorder = self.clone();
        tokio::spawn(async move {
            let mut builder = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10));
            if let Some(address) = recorder.config.connect_address
                && let Ok(url) = url::Url::parse(&recorder.config.endpoint)
                && let Some(host) = url.host_str()
            {
                builder = builder.resolve(
                    host,
                    std::net::SocketAddr::new(address, url.port_or_known_default().unwrap_or(443)),
                );
            }
            if let Some(pem) = &recorder.config.tls_identity_pem {
                if let Ok(identity) = reqwest::Identity::from_pem(pem.as_bytes()) {
                    builder = builder.identity(identity);
                } else {
                    tracing::error!("usage TLS identity is invalid");
                    return;
                }
            }
            if let Some(pem) = &recorder.config.tls_ca_pem {
                if let Ok(certificate) = reqwest::Certificate::from_pem(pem.as_bytes()) {
                    builder = builder.add_root_certificate(certificate);
                } else {
                    tracing::error!("usage TLS CA is invalid");
                    return;
                }
            }
            let Ok(client) = builder.build() else {
                tracing::error!("usage sender initialization failed");
                return;
            };
            let mut delay = 10;
            loop {
                tokio::time::sleep(Duration::from_secs(delay)).await;
                // A bounded drain cycle prevents an old queue from starving
                // other work. Exactly one HTTP request is in flight.
                let mut successful = true;
                for _ in 0..16 {
                    let store = recorder.clone();
                    let Ok(Ok(batch)) = tokio::task::spawn_blocking(move || store.batch()).await
                    else {
                        successful = false;
                        break;
                    };
                    if batch.is_empty() {
                        break;
                    }
                    let response = client
                        .post(&recorder.config.endpoint)
                        .bearer_auth(&recorder.config.token)
                        .json(&serde_json::json!({"buckets":batch}))
                        .send()
                        .await;
                    let Ok(response) = response else {
                        successful = false;
                        break;
                    };
                    if !response.status().is_success() {
                        successful = false;
                        break;
                    }
                    if response.content_length().is_some_and(|n| n > 65_536) {
                        successful = false;
                        break;
                    }
                    let mut bytes = Vec::new();
                    let mut stream = response.bytes_stream();
                    while let Some(chunk) = stream.next().await {
                        match chunk {
                            Ok(c) if bytes.len() + c.len() <= 65_536 => bytes.extend_from_slice(&c),
                            _ => {
                                successful = false;
                                break;
                            }
                        }
                    }
                    if !successful {
                        break;
                    }
                    let Ok(ack) = serde_json::from_slice::<Acknowledgment>(&bytes) else {
                        successful = false;
                        break;
                    };
                    if ack.results.len() != batch.len() {
                        successful = false;
                        break;
                    }
                    let mut acknowledgments = Vec::new();
                    for (bucket, result) in batch.into_iter().zip(ack.results) {
                        if bucket.bucket_id != result.bucket_id
                            || bucket.revision != result.revision
                        {
                            successful = false;
                            break;
                        }
                        let quarantine = match result.status.as_str() {
                            "accepted" | "unknown_key" | "stale" => false,
                            "conflict" | "invalid" => true,
                            _ => {
                                successful = false;
                                break;
                            }
                        };
                        acknowledgments.push((bucket, quarantine));
                        if quarantine {
                            tracing::error!("usage snapshot requires reconciliation");
                        }
                    }
                    if !successful {
                        break;
                    }
                    let store = recorder.clone();
                    if !matches!(
                        tokio::task::spawn_blocking(
                            move || store.acknowledge_batch(&acknowledgments, now_ms())
                        )
                        .await,
                        Ok(Ok(()))
                    ) {
                        successful = false;
                        break;
                    }
                }
                delay = if successful {
                    10
                } else {
                    tracing::warn!("usage delivery delayed");
                    (delay * 2).min(120)
                };
            }
        });
    }
}

/// These routes must be wrapped in the gateway's signed-admin middleware.
pub fn admin_router(recorder: Arc<Recorder>) -> axum::Router {
    use axum::{
        Json,
        extract::State,
        routing::{get, post},
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Replay {
        from_ms: u64,
    }
    axum::Router::new()
        .route(
            "/admin/v1/usage/status",
            get(|State(recorder): State<Arc<Recorder>>| async move { Json(recorder.status()) }),
        )
        .route(
            "/admin/v1/usage/replay",
            post(
                |State(recorder): State<Arc<Recorder>>, Json(input): Json<Replay>| async move {
                    let result = tokio::task::spawn_blocking(move || {
                        recorder.replay(input.from_ms, now_ms())
                    })
                    .await;
                    match result {
                        Ok(Ok(count)) => (
                            axum::http::StatusCode::OK,
                            Json(serde_json::json!({"requeued_buckets":count})),
                        ),
                        Ok(Err(Error::Config)) => (
                            axum::http::StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({"code":"invalid_replay_window"})),
                        ),
                        _ => (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({"code":"usage_storage_unavailable"})),
                        ),
                    }
                },
            ),
        )
        .with_state(recorder)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acknowledgment {
    results: Vec<Ack>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    bucket_id: String,
    revision: u64,
    status: String,
}

/// A transient request guard. Dropping a client response settles cancellation.
/// This guard stores numbers and approved identity fields only.
pub struct RequestUsage {
    recorder: Arc<Recorder>,
    key_id: String,
    requested_model: String,
    model: Model,
    pub observation: Observation,
    outcome: Outcome,
    ended_at: Option<u64>,
}

impl RequestUsage {
    #[must_use]
    pub fn served_model(&self) -> &str {
        &self.model.served_model
    }
    pub fn finish(&mut self, outcome: Outcome) {
        self.outcome = outcome;
        self.ended_at = Some(now_ms());
    }
}
impl Drop for RequestUsage {
    fn drop(&mut self) {
        if self
            .recorder
            .record(
                &self.key_id,
                &self.requested_model,
                &self.model,
                self.observation,
                self.outcome,
                self.ended_at.unwrap_or_else(now_ms),
            )
            .is_err()
        {
            if let Ok(mut state) = self.recorder.state.lock() {
                state.storage_failed = true;
            }
            tracing::error!("usage aggregation failed");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            environment: "staging".into(),
            cluster_id: "cluster-1".into(),
            key_realm: "staging".into(),
            producer_id: "producer-1".into(),
            endpoint: "https://admin.example.test/api/usage/ingest".into(),
            token: "a".repeat(48),
            tls_identity_pem: None,
            tls_ca_pem: None,
            connect_address: None,
            models: BTreeMap::from([(
                "model-a".into(),
                Model {
                    served_model: "model-a".into(),
                    model_revision: "revision-1".into(),
                },
            )]),
            max_buckets: 16,
            max_database_bytes: 4_194_304,
            acknowledged_retention_seconds: 3600,
        }
    }

    fn add(store: &Arc<Recorder>, key: &str, at: u64, input: u64, output: u64) {
        let mut request = store.reserve(key, "model-a").unwrap();
        request.observation = Observation {
            input: Some(input),
            output: Some(output),
            cached: Some(0),
            reasoning: None,
            final_usage: true,
        };
        request.outcome = Outcome::Completed;
        request.ended_at = Some(at);
    }

    #[test]
    fn aggregates_restarts_and_never_sends_unflushed_updates() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage.sqlite3");
        let store = Recorder::open(&path, config()).unwrap();
        add(&store, "key_abc", 60_001, 100, 10);
        add(&store, "key_abc", 60_002, 200, 20);
        assert!(store.batch().unwrap().is_empty());
        store.flush(60_003).unwrap();
        let batch = store.batch().unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].counts.requests, 2);
        assert_eq!(batch[0].counts.input_tokens, 300);
        assert_eq!(batch[0].counts.reasoning_known, 0);
        assert_eq!(batch[0].revision, 1);
        add(&store, "key_abc", 60_004, 500, 50);
        assert_eq!(store.batch().unwrap()[0], batch[0]);
        drop(store); // Unflushed counts are intentionally lost in v1.
        let reopened = Recorder::open(&path, config()).unwrap();
        assert_eq!(reopened.batch().unwrap(), batch);
        add(&reopened, "key_abc", 60_005, 20, 2);
        reopened.flush(60_006).unwrap();
        assert_eq!(reopened.batch().unwrap()[0].revision, 2);
        assert_eq!(reopened.batch().unwrap()[0].counts.input_tokens, 320);
        assert!(
            Recorder::open(
                &path,
                Config {
                    producer_id: "wrong".into(),
                    ..config()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn acknowledgment_cannot_hide_a_newer_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let store = Recorder::open(&directory.path().join("usage.sqlite3"), config()).unwrap();
        add(&store, "key_abc", 60_001, 100, 10);
        store.flush(60_002).unwrap();
        let old = store.batch().unwrap().remove(0);
        add(&store, "key_abc", 60_003, 20, 2);
        store.flush(60_004).unwrap();
        store.acknowledge(&old, 60_005, false).unwrap();
        let new = store.batch().unwrap().remove(0);
        assert_eq!(new.revision, 2);
        store.acknowledge(&new, 60_006, false).unwrap();
        assert!(store.batch().unwrap().is_empty());
        assert_eq!(store.replay(60_000, 60_007).unwrap(), 1);
        assert_eq!(store.batch().unwrap()[0], new);
        store.acknowledge(&new, 60_008, false).unwrap();
        assert!(store.replay(0, 3_700_000).is_err());
        store.flush(3_700_000).unwrap();
        assert!(store.state.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn reserves_capacity_for_inflight_completions_and_bounds_batches() {
        let directory = tempfile::tempdir().unwrap();
        let store = Recorder::open(&directory.path().join("usage.sqlite3"), config()).unwrap();
        let guards: Vec<_> = (0..16)
            .map(|i| store.reserve(&format!("key_{i}"), "model-a").unwrap())
            .collect();
        assert!(matches!(
            store.reserve("key_full", "model-a"),
            Err(Error::Capacity)
        ));
        drop(guards);
        store.flush(now_ms()).unwrap();
        let batch = store.batch().unwrap();
        assert_eq!(batch.len(), 16);
        assert!(
            batch
                .iter()
                .all(|b| b.counts.cancelled == 1 && b.counts.unavailable_usage == 1)
        );
        assert!(
            serde_json::to_vec(&serde_json::json!({"buckets": batch}))
                .unwrap()
                .len()
                <= MAX_BATCH_BYTES
        );
        assert!(store.reserve("authorization=secret", "model-a").is_err());
        assert!(store.reserve("key_abc", "unapproved-model").is_err());
    }
}
