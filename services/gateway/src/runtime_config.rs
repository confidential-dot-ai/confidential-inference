//! Complete mounted configuration snapshots. Request handlers only read memory.

use std::{
    fs,
    io::Read as _,
    path::{Path, PathBuf},
    sync::{Arc, RwLock, Weak},
    time::Duration,
};

use notify::{RecursiveMode, Watcher as _};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

/// A document revision increases for every change, including a rollback.
pub trait Versioned {
    fn revision(&self) -> u64;
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReloadStatus {
    pub desired_revision: Option<u64>,
    pub desired_sha256: Option<String>,
    pub accepted_revision: u64,
    pub accepted_sha256: String,
    pub error: Option<String>,
    pub watcher_error: bool,
    pub watcher_active: bool,
    pub retired_snapshot_readers: std::collections::BTreeMap<u64, usize>,
}

struct State<T> {
    accepted: Arc<T>,
    status: ReloadStatus,
    retired: std::collections::BTreeMap<u64, Weak<T>>,
}

/// Validation must finish before one complete snapshot becomes visible.
pub struct MountedConfig<T> {
    path: PathBuf,
    limit: usize,
    state: RwLock<State<T>>,
}

impl<T: DeserializeOwned + Versioned> MountedConfig<T> {
    /// Invalid or absent startup data stops startup. No defaults are substituted.
    ///
    /// # Errors
    /// Returns an error when the file or its complete document is invalid.
    pub fn open(
        path: PathBuf,
        limit: usize,
        validate: impl Fn(&T) -> Result<(), String>,
    ) -> Result<Self, String> {
        let (document, hash) = read_document::<T>(&path, limit)?;
        validate(&document)?;
        let revision = document.revision();
        Ok(Self {
            path,
            limit,
            state: RwLock::new(State {
                accepted: Arc::new(document),
                status: ReloadStatus {
                    desired_revision: Some(revision),
                    desired_sha256: Some(hash.clone()),
                    accepted_revision: revision,
                    accepted_sha256: hash,
                    error: None,
                    watcher_error: false,
                    watcher_active: false,
                    retired_snapshot_readers: std::collections::BTreeMap::new(),
                },
                retired: std::collections::BTreeMap::new(),
            }),
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<T> {
        // Only this module writes the lock. No user validation runs under it.
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accepted
            .clone()
    }

    #[must_use]
    pub fn status(&self) -> ReloadStatus {
        let state = self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut status = state.status.clone();
        status.retired_snapshot_readers = state
            .retired
            .iter()
            .filter_map(|(revision, snapshot)| {
                let count = snapshot.strong_count();
                (count > 0).then_some((*revision, count))
            })
            .collect();
        status
    }

    /// Retry pending documents even when the bytes have not changed. For
    /// example, a router backend can become ready after the file arrived.
    pub fn refresh(&self, validate: impl Fn(&T) -> Result<(), String>) {
        let read = read_document::<T>(&self.path, self.limit);
        let validation = read.as_ref().ok().map(|(document, _)| validate(document));
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (document, hash) = match read {
            Ok(value) => value,
            Err(error) => {
                state.status.desired_revision = None;
                state.status.desired_sha256 = None;
                state.status.error = Some(error);
                return;
            }
        };
        let revision = document.revision();
        state.status.desired_revision = Some(revision);
        state.status.desired_sha256 = Some(hash.clone());
        if revision < state.status.accepted_revision
            || (revision == state.status.accepted_revision && hash != state.status.accepted_sha256)
        {
            state.status.error =
                Some("configuration revision must increase when bytes change".into());
            return;
        }
        if hash == state.status.accepted_sha256 {
            state.status.error = None;
            return;
        }
        if let Some(Err(error)) = validation {
            state.status.error = Some(error);
            return;
        }
        state
            .retired
            .retain(|_, snapshot| snapshot.strong_count() > 0);
        if state.retired.len() >= 64 && Arc::strong_count(&state.accepted) > 1 {
            state.status.error =
                Some("too many retained configuration snapshots; wait for request drain".into());
            return;
        }
        let previous_revision = state.status.accepted_revision;
        let previous = Arc::downgrade(&state.accepted);
        state.retired.insert(previous_revision, previous);
        state.accepted = Arc::new(document);
        state.status.accepted_revision = revision;
        state.status.accepted_sha256 = hash;
        state.status.error = None;
    }
}

impl<T: DeserializeOwned + Versioned + Send + Sync + 'static> MountedConfig<T> {
    /// Watch the mount directory, not a generation file. Polling also retries
    /// pending data and recovers from lost events or watcher failure.
    pub fn watch(
        self: &Arc<Self>,
        validate: impl Fn(&T) -> Result<(), String> + Send + Sync + 'static,
        poll_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let source = self.clone();
        let validate = Arc::new(validate);
        tokio::spawn(async move {
            let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
            let mut watcher =
                notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                    let _ = sender.try_send(event.is_ok());
                })
                .ok();
            let directory = source.path.parent().unwrap_or_else(|| Path::new("."));
            let mut watching = watcher.as_mut().is_some_and(|watcher| {
                watcher
                    .watch(directory, RecursiveMode::NonRecursive)
                    .is_ok()
            });
            source
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .status
                .watcher_error = !watching;
            source
                .state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .status
                .watcher_active = watching;
            let mut interval = tokio::time::interval(poll_interval.max(Duration::from_millis(100)));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = interval.tick() => {},
                    event = receiver.recv(), if watching => {
                        if event != Some(true) {
                            source.state.write().unwrap_or_else(std::sync::PoisonError::into_inner).status.watcher_error = true;
                            if event.is_none() {
                                watching = false;
                                source.state.write().unwrap_or_else(std::sync::PoisonError::into_inner).status.watcher_active = false;
                            }
                        }
                        // Coalesce an atomic-writer event burst.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
                let current = source.clone();
                let check = validate.clone();
                if tokio::task::spawn_blocking(move || current.refresh(|document| check(document)))
                    .await
                    .is_err()
                {
                    source
                        .state
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .status
                        .error = Some("configuration reload task failed".into());
                }
            }
        })
    }
}

fn read_document<T: DeserializeOwned>(path: &Path, limit: usize) -> Result<(T, String), String> {
    if limit == 0 || limit > 1024 * 1024 {
        return Err("invalid configuration byte limit".into());
    }
    // Resolve the mount root first. One canonical file and opened handle
    // select one atomic-writer generation, even if ..data changes afterwards.
    let root = fs::canonicalize(path.parent().unwrap_or_else(|| Path::new(".")))
        .map_err(|_| "configuration directory is unavailable")?;
    let target = fs::canonicalize(path).map_err(|_| "configuration file is unavailable")?;
    if target == root || !target.starts_with(&root) {
        return Err("configuration file leaves its directory".into());
    }
    let safe = |metadata: &fs::Metadata| {
        metadata.is_file() && metadata.len() > 0 && metadata.len() <= limit as u64
    };
    if !safe(&fs::symlink_metadata(&target).map_err(|_| "configuration file is unavailable")?) {
        return Err("configuration file has an unsafe shape".into());
    }
    let file = fs::File::open(target).map_err(|_| "configuration file is unavailable")?;
    if !safe(
        &file
            .metadata()
            .map_err(|_| "configuration file is unavailable")?,
    ) {
        return Err("configuration file has an unsafe shape".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "configuration file read failed")?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("configuration file exceeds its byte limit".into());
    }
    let document = serde_json::from_slice(&bytes).map_err(|_| "invalid configuration JSON")?;
    Ok((document, format!("sha256:{:x}", Sha256::digest(bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Document {
        revision: u64,
        value: String,
    }
    impl Versioned for Document {
        fn revision(&self) -> u64 {
            self.revision
        }
    }
    fn valid(document: &Document) -> Result<(), String> {
        if document.value.is_empty() {
            Err("empty value".into())
        } else {
            Ok(())
        }
    }
    #[test]
    fn invalid_updates_keep_active_snapshots_and_restart_fails_closed()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        fs::write(&path, br#"{"revision":1,"value":"old"}"#)?;
        let source = MountedConfig::<Document>::open(path.clone(), 1024, valid)?;
        let active = source.snapshot();
        fs::write(&path, br#"{"revision":2,"value":""}"#)?;
        source.refresh(valid);
        assert_eq!(source.snapshot().value, "old");
        assert_eq!(source.status().desired_revision, Some(2));
        assert!(source.status().error.is_some());
        assert!(MountedConfig::<Document>::open(path.clone(), 1024, valid).is_err());
        fs::write(&path, br#"{"revision":3,"value":"new"}"#)?;
        source.refresh(valid);
        assert_eq!(source.snapshot().value, "new");
        assert_eq!(active.value, "old");
        assert_eq!(source.status().retired_snapshot_readers.get(&1), Some(&1));
        drop(active);
        assert!(source.status().retired_snapshot_readers.is_empty());
        fs::write(&path, br#"{"revision":1,"value":"old"}"#)?;
        source.refresh(valid);
        assert_eq!(source.snapshot().value, "new");
        fs::write(&path, br#"{"revision":4,"value":"old"}"#)?;
        source.refresh(valid);
        assert_eq!(source.snapshot().value, "old");
        Ok(())
    }
    #[test]
    fn pending_document_retries_without_a_file_change() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.json");
        fs::write(&path, br#"{"revision":1,"value":"old"}"#)?;
        let source = MountedConfig::<Document>::open(path.clone(), 1024, valid)?;
        fs::write(&path, br#"{"revision":2,"value":"new"}"#)?;
        source.refresh(|_| Err("backend is not ready".into()));
        assert_eq!(source.status().accepted_revision, 1);
        source.refresh(valid);
        assert_eq!(source.status().accepted_revision, 2);
        fs::write(&path, br#"{"revision":2,"value":"changed"}"#)?;
        source.refresh(valid);
        assert_eq!(source.snapshot().value, "new");
        Ok(())
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn directory_watch_follows_projection_swaps_and_polling_recovers()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir()?;
        for (generation, revision) in [("..one", 1), ("..two", 2)] {
            fs::create_dir(dir.path().join(generation))?;
            fs::write(
                dir.path().join(generation).join("config.json"),
                format!(r#"{{"revision":{revision},"value":"{generation}"}}"#),
            )?;
        }
        symlink("..one", dir.path().join("..data"))?;
        symlink("..data/config.json", dir.path().join("config.json"))?;
        let source = Arc::new(MountedConfig::<Document>::open(
            dir.path().join("config.json"),
            1024,
            valid,
        )?);
        let task = source.watch(valid, Duration::from_secs(30));
        tokio::time::timeout(Duration::from_secs(3), async {
            while !source.status().watcher_active {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        symlink("..two", dir.path().join("..next"))?;
        fs::rename(dir.path().join("..next"), dir.path().join("..data"))?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while source.status().accepted_revision != 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        task.abort();
        let outside = tempfile::NamedTempFile::new()?;
        fs::remove_file(dir.path().join("config.json"))?;
        symlink(outside.path(), dir.path().join("config.json"))?;
        assert!(
            MountedConfig::<Document>::open(dir.path().join("config.json"), 1024, valid).is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn polling_accepts_configuration_when_the_watch_cannot_start()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let mount = directory.path().join("mount");
        fs::create_dir(&mount)?;
        let path = mount.join("config.json");
        fs::write(&path, br#"{"revision":1,"value":"old"}"#)?;
        let source = Arc::new(MountedConfig::<Document>::open(path, 1024, valid)?);
        fs::rename(&mount, directory.path().join("old-mount"))?;
        let task = source.watch(valid, Duration::from_millis(100));
        tokio::time::timeout(Duration::from_secs(3), async {
            while !source.status().watcher_error {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        assert!(!source.status().watcher_active);
        fs::create_dir(&mount)?;
        fs::write(
            mount.join("config.json"),
            br#"{"revision":2,"value":"new"}"#,
        )?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while source.status().accepted_revision != 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        assert_eq!(source.snapshot().value, "new");
        task.abort();
        Ok(())
    }
}
