//! Public policy metadata. Only CDS and C8s discovery are upstream sources.

use crate::{
    AttestationError, AttestationProvider, metrics::GatewayMetrics,
    runtime_settings::EvidenceSettings,
};
use base64::Engine as _;
use futures_util::StreamExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    io::{Cursor, Write as _},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt as _, process::Command, sync::Mutex};
use url::Url;

fn unavailable(step: &str) -> AttestationError {
    AttestationError::Unavailable(step.to_owned())
}

#[async_trait::async_trait]
pub trait MetadataSource: Send + Sync {
    async fn fetch(&self) -> Result<Value, AttestationError>;

    /// Use one address snapshot for this complete refresh.
    async fn fetch_with_evidence(
        &self,
        _evidence: Option<&EvidenceEndpoint>,
    ) -> Result<Value, AttestationError> {
        self.fetch().await
    }
}

/// Prepared client for one accepted evidence-address snapshot.
#[derive(Clone)]
pub struct EvidenceEndpoint {
    pub discovery_url: Url,
    pub allowlist_url: Url,
    pub client: reqwest::Client,
}

impl EvidenceEndpoint {
    fn new(
        settings: &EvidenceSettings,
        timeout: Duration,
        roots: &[reqwest::Certificate],
    ) -> Result<Self, AttestationError> {
        settings.validate().map_err(|error| unavailable(&error))?;
        let base =
            Url::parse(&settings.base_url).map_err(|_| unavailable("invalid evidence URL"))?;
        let mut client = reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .redirect(reqwest::redirect::Policy::none());
        if let Some(host) = &settings.connect_host {
            client = crate::attestation::evidence_connection(client, &base, host)
                .map_err(|error| unavailable(&error))?;
        }
        for certificate in roots {
            client = client.add_root_certificate(certificate.clone());
        }
        Ok(Self {
            discovery_url: base
                .join("v1/discovery")
                .map_err(|_| unavailable("invalid discovery URL"))?,
            allowlist_url: base
                .join("allowlist")
                .map_err(|_| unavailable("invalid allowlist URL"))?,
            client: client
                .build()
                .map_err(|_| unavailable("build discovery client"))?,
        })
    }
}

#[derive(Default)]
struct MetadataCache {
    evidence: Option<EvidenceSettings>,
    endpoint: Option<EvidenceEndpoint>,
    response: Option<(Instant, Result<Value, AttestationError>)>,
}

/// A short successful cache and a short failure cooldown bound CDS load.
/// The same mutex serializes refreshes. Expired documents are never returned.
pub struct MetadataProvider {
    source: Arc<dyn MetadataSource>,
    cache: Mutex<MetadataCache>,
    ttl: Duration,
    timeout: Duration,
    maximum_bytes: usize,
    metrics: Arc<GatewayMetrics>,
    discovery_roots: Vec<reqwest::Certificate>,
    runtime:
        Option<Arc<crate::runtime_config::MountedConfig<crate::runtime_settings::GatewaySettings>>>,
}

impl MetadataProvider {
    /// Create a bounded metadata cache.
    ///
    /// # Errors
    /// Return an error if a cache, timeout, or response limit is invalid.
    pub fn new(
        source: Arc<dyn MetadataSource>,
        ttl: Duration,
        timeout: Duration,
        maximum_bytes: usize,
        metrics: Arc<GatewayMetrics>,
    ) -> Result<Self, String> {
        if ttl.is_zero()
            || ttl > Duration::from_secs(30)
            || timeout.is_zero()
            || timeout > Duration::from_secs(120)
            || !(1024..=8 * 1024 * 1024).contains(&maximum_bytes)
        {
            return Err("invalid metadata cache limits".into());
        }
        Ok(Self {
            source,
            cache: Mutex::new(MetadataCache::default()),
            ttl,
            timeout,
            maximum_bytes,
            metrics,
            discovery_roots: crate::attestation::mesh_ca_certificates()?,
            runtime: None,
        })
    }

    #[must_use]
    pub fn with_runtime(
        mut self,
        runtime: Option<
            Arc<crate::runtime_config::MountedConfig<crate::runtime_settings::GatewaySettings>>,
        >,
    ) -> Self {
        self.runtime = runtime;
        self
    }
}

#[async_trait::async_trait]
impl AttestationProvider for MetadataProvider {
    fn requires_nonce(&self) -> bool {
        false
    }

    async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
        // Bound waiters as well as the refresh. The HTTP handler also has an
        // existing non-waiting attestation concurrency limit.
        let mut cache = tokio::time::timeout(self.timeout, self.cache.lock())
            .await
            .map_err(|_| unavailable("metadata cache wait timed out"))?;
        let settings = self.runtime.as_ref().map(|config| config.snapshot());
        let evidence = settings
            .as_ref()
            .and_then(|settings| settings.evidence.clone());
        // Address changes invalidate both successful results and failure cooldowns.
        // A refresh already in progress keeps its complete old address snapshot.
        if cache.evidence != evidence {
            cache.evidence = evidence;
            cache.endpoint = None;
            cache.response = None;
        }
        let ttl = settings.as_ref().map_or(self.ttl, |settings| {
            Duration::from_secs(settings.attestation_cache_seconds)
        });
        if let Some((created, result)) = &cache.response
            && created.elapsed()
                < if result.is_ok() {
                    ttl
                } else {
                    Duration::from_secs(1)
                }
        {
            self.metrics.record_attestation_event(if result.is_ok() {
                "cache_hit"
            } else {
                "failure_cooldown"
            });
            return result.clone();
        }
        self.metrics.record_attestation_event("cache_miss");
        let refresh = async {
            if cache.endpoint.is_none()
                && let Some(evidence) = &cache.evidence
            {
                cache.endpoint = Some(EvidenceEndpoint::new(
                    evidence,
                    self.timeout,
                    &self.discovery_roots,
                )?);
            }
            self.source
                .fetch_with_evidence(cache.endpoint.as_ref())
                .await
        };
        let result = match tokio::time::timeout(self.timeout, refresh).await {
            Ok(Ok(value))
                if serde_json::to_vec(&value)
                    .map_or(true, |bytes| bytes.len() > self.maximum_bytes) =>
            {
                Err(unavailable("metadata response exceeds the byte limit"))
            }
            Ok(result) => result,
            Err(_) => Err(unavailable("metadata refresh timed out")),
        };
        self.metrics.record_attestation_event(if result.is_ok() {
            "refresh_ok"
        } else {
            "refresh_failed"
        });
        cache.response = Some((Instant::now(), result.clone()));
        result
    }
}

pub struct CdsMetadataSource {
    pub cds_url: Url,
    pub discovery_url: Url,
    pub allowlist_url: Url,
    pub release_id: String,
    pub release_url: Url,
    pub bundle_sha256: String,
    pub verifier: PathBuf,
    pub image_policy: PathBuf,
    pub image_policy_sha256: String,
    pub served_image_policy: PathBuf,
    pub served_image_policy_sha256: String,
    pub timeout: Duration,
    pub maximum_bytes: usize,
    pub discovery_client: reqwest::Client,
}

async fn bounded_body(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, AttestationError> {
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(unavailable("CDS response exceeds the byte limit"));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| unavailable("read CDS response"))?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(unavailable("CDS response exceeds the byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn pinned_image_policy(
    path: &std::path::Path,
    digest: &str,
) -> Result<tempfile::NamedTempFile, AttestationError> {
    // Hash and copy the same bounded read. The verifier must not reopen a
    // mutable ConfigMap after its hash was checked.
    let policy = tokio::fs::File::open(path)
        .await
        .map_err(|_| unavailable("read CDS image policy"))?;
    let mut bytes = Vec::new();
    policy
        .take(256 * 1024 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| unavailable("read CDS image policy"))?;
    if bytes.len() > 256 * 1024 {
        return Err(unavailable("CDS image policy exceeds the byte limit"));
    }
    if format!("sha256:{:x}", Sha256::digest(&bytes)) != digest {
        return Err(unavailable("CDS image policy hash mismatch"));
    }
    let mut pinned = tempfile::NamedTempFile::new()
        .map_err(|_| unavailable("create pinned CDS image policy"))?;
    pinned
        .write_all(&bytes)
        .map_err(|_| unavailable("write pinned CDS image policy"))?;
    // from_reader below starts at the beginning of the checked bytes.
    std::io::Seek::rewind(pinned.as_file_mut())
        .map_err(|_| unavailable("rewind pinned CDS image policy"))?;
    Ok(pinned)
}

impl CdsMetadataSource {
    async fn verify_cds(&self) -> Result<Value, AttestationError> {
        let pinned_policy =
            pinned_image_policy(&self.image_policy, &self.image_policy_sha256).await?;
        let pinned_served =
            pinned_image_policy(&self.served_image_policy, &self.served_image_policy_sha256)
                .await?;
        let target: Value = serde_json::from_reader(pinned_policy.as_file())
            .map_err(|_| unavailable("invalid CDS target image policy"))?;
        if target
            .get("measurements")
            .and_then(Value::as_array)
            .is_none_or(|entries| entries.len() != 1)
        {
            return Err(unavailable(
                "CDS target image policy must pin one control-node identity",
            ));
        }
        let mut child = Command::new(&self.verifier)
            .args([
                "verify",
                self.cds_url.as_str(),
                "--kind",
                "cds",
                "--mode",
                "armtls-cert",
                "--image-policy-file",
            ])
            .arg(pinned_policy.path())
            .arg("--served-policy-file")
            .arg(pinned_served.path())
            .args(["--output", "json"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| unavailable("start CDS verifier"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| unavailable("read CDS verifier"))?;
        let mut bytes = Vec::new();
        stdout
            .take(256 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| unavailable("read CDS verifier"))?;
        if bytes.len() > 256 * 1024 {
            return Err(unavailable("CDS verifier output exceeds the byte limit"));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| unavailable("wait for CDS verifier"))?;
        let verdict: Value =
            serde_json::from_slice(&bytes).map_err(|_| unavailable("decode CDS verification"))?;
        if !status.success() || verdict["verified"] != true || verdict["measurement_pinned"] != true
        {
            return Err(unavailable("CDS attestation failed"));
        }
        if verdict
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(|warnings| !warnings.is_empty())
        {
            return Err(unavailable("CDS attestation has unresolved trust warnings"));
        }
        if verdict
            .get("operator_keys_note")
            .and_then(Value::as_str)
            .is_some_and(|note| {
                note.contains("could not")
                    || note.contains("failed")
                    || note.contains("skipped")
                    || note.contains("not fetched")
            })
        {
            return Err(unavailable("CDS operator-key verification failed"));
        }
        Ok(verdict)
    }

    async fn cds_read(
        &self,
        client: &reqwest::Client,
        route: &str,
        certificate_sha256: &str,
    ) -> Result<reqwest::Response, AttestationError> {
        let url = self
            .cds_url
            .join(route)
            .map_err(|_| unavailable("invalid CDS route"))?;
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| unavailable("read attested CDS"))?;
        // This GET carries no credentials. Accept data only if the response
        // came over the exact certificate verified above. A different leaf,
        // a redirect, or missing TLS data never supplies policy or keys.
        let certificate = response
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(reqwest::tls::TlsInfo::peer_certificate)
            .ok_or_else(|| unavailable("CDS connection has no certificate"))?;
        if format!("{:x}", Sha256::digest(certificate)) != certificate_sha256 {
            return Err(unavailable("CDS certificate changed after verification"));
        }
        Ok(response)
    }
}

fn operator_keys(bytes: &[u8], verdict: &Value) -> Result<Vec<String>, AttestationError> {
    let mut keys = Vec::new();
    let mut fingerprints = BTreeSet::new();
    for item in rustls_pemfile::read_all(&mut Cursor::new(bytes)) {
        let item = item.map_err(|_| unavailable("invalid CDS public-key PEM"))?;
        let rustls_pemfile::Item::SubjectPublicKeyInfo(der) = item else {
            return Err(unavailable("CDS operator keys contain other PEM material"));
        };
        fingerprints.insert(format!("{:x}", Sha256::digest(der.as_ref())));
        let encoded = base64::engine::general_purpose::STANDARD.encode(der.as_ref());
        let lines = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| String::from_utf8_lossy(line))
            .collect::<Vec<_>>()
            .join("\n");
        keys.push(format!(
            "-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n"
        ));
    }
    let verified = verdict
        .get("operator_keys")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    if keys.is_empty() || keys.len() > 32 || fingerprints != verified {
        return Err(unavailable(
            "CDS public keys differ from the verified key set",
        ));
    }
    Ok(keys)
}

#[async_trait::async_trait]
impl MetadataSource for CdsMetadataSource {
    async fn fetch(&self) -> Result<Value, AttestationError> {
        self.fetch_with_evidence(None).await
    }

    async fn fetch_with_evidence(
        &self,
        evidence: Option<&EvidenceEndpoint>,
    ) -> Result<Value, AttestationError> {
        let discovery_url =
            evidence.map_or(&self.discovery_url, |endpoint| &endpoint.discovery_url);
        let allowlist_url =
            evidence.map_or(&self.allowlist_url, |endpoint| &endpoint.allowlist_url);
        let discovery_client = evidence.map_or(&self.discovery_client, |endpoint| &endpoint.client);
        let verdict = self.verify_cds().await?;
        let certificate = verdict["cert_sha256"]
            .as_str()
            .filter(|value| value.len() == 64)
            .ok_or_else(|| unavailable("CDS verifier returned no certificate hash"))?;
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .tls_info(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(self.timeout)
            .build()
            .map_err(|_| unavailable("build attested CDS reader"))?;
        let (policy, keys, discovery) = tokio::join!(
            self.cds_read(&client, "/allowlist", certificate),
            self.cds_read(&client, "/operator-keys", certificate),
            discovery_client.get(discovery_url.clone()).send()
        );
        let policy = policy?;
        if policy.status() != reqwest::StatusCode::OK {
            return Err(unavailable("CDS policy read failed"));
        }
        let policy_bytes = bounded_body(policy, self.maximum_bytes).await?;
        let policy: Value = serde_json::from_slice(&policy_bytes)
            .map_err(|_| unavailable("invalid CDS policy JSON"))?;
        crate::attestation::validate_allowlist(&policy, &policy_bytes)?;
        let keys = keys?;
        let keys = if keys.status() == reqwest::StatusCode::NOT_FOUND {
            let bytes = bounded_body(keys, 256 * 1024).await?;
            if !bytes.starts_with(b"no operator keys configured")
                || verdict
                    .get("operator_keys")
                    .and_then(Value::as_array)
                    .is_some_and(|keys| !keys.is_empty())
            {
                return Err(unavailable("CDS key absence was not confirmed"));
            }
            vec![]
        } else if keys.status() == reqwest::StatusCode::OK {
            operator_keys(&bounded_body(keys, 256 * 1024).await?, &verdict)?
        } else {
            return Err(unavailable("CDS operator-key read failed"));
        };
        let discovery = discovery.map_err(|_| unavailable("read C8s discovery"))?;
        if discovery.status() != reqwest::StatusCode::OK {
            return Err(unavailable("C8s discovery read failed"));
        }
        let discovery: Value =
            serde_json::from_slice(&bounded_body(discovery, self.maximum_bytes).await?)
                .map_err(|_| unavailable("invalid C8s discovery JSON"))?;
        crate::attestation::validate_discovery(&discovery)?;
        Ok(json!({"schemaVersion": 3,
            "release": {"id": self.release_id, "url": self.release_url.as_str(), "bundleSha256": self.bundle_sha256},
            "c8s": {"activeAllowlist": {"document": policy, "sha256": format!("sha256:{:x}", Sha256::digest(&policy_bytes)),
                        "url": allowlist_url.as_str()}, "discovery": discovery, "operatorKeys": keys}}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Source {
        calls: AtomicUsize,
        fail: AtomicBool,
        delay: Duration,
        document: Value,
    }

    #[async_trait::async_trait]
    impl MetadataSource for Source {
        async fn fetch(&self) -> Result<Value, AttestationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            if self.fail.load(Ordering::SeqCst) {
                Err(unavailable("test source failed"))
            } else {
                Ok(self.document.clone())
            }
        }
    }

    fn source(document: Value, delay: Duration) -> Arc<Source> {
        Arc::new(Source {
            calls: AtomicUsize::new(0),
            fail: AtomicBool::new(false),
            delay,
            document,
        })
    }

    fn provider(source: Arc<Source>, ttl: Duration, timeout: Duration) -> MetadataProvider {
        MetadataProvider::new(
            source,
            ttl,
            timeout,
            1024,
            Arc::new(GatewayMetrics::new("test")),
        )
        .unwrap_or_else(|error| panic!("{error:?}"))
    }

    #[tokio::test]
    async fn simultaneous_requests_share_one_refresh_without_nonce() {
        let source = source(json!({"schemaVersion": 3}), Duration::from_millis(10));
        let provider = Arc::new(provider(
            source.clone(),
            Duration::from_secs(10),
            Duration::from_secs(1),
        ));
        assert!(!provider.requires_nonce());
        let responses = futures_util::future::join_all((0..32).map(|_| {
            let provider = provider.clone();
            async move { provider.response(&[0; 32]).await }
        }))
        .await;
        assert!(responses.iter().all(Result::is_ok));
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_failure_never_returns_expired_success() {
        let source = source(json!({"schemaVersion": 3}), Duration::ZERO);
        let provider = provider(
            source.clone(),
            Duration::from_millis(5),
            Duration::from_secs(1),
        );
        assert!(provider.response(&[0; 32]).await.is_ok());
        source.fail.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(provider.response(&[0; 32]).await.is_err());
        assert!(provider.response(&[0; 32]).await.is_err());
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn timeout_is_an_error_and_has_a_failure_cooldown() {
        let source = source(json!({}), Duration::from_secs(1));
        let provider = provider(
            source.clone(),
            Duration::from_secs(10),
            Duration::from_millis(10),
        );
        let started = Instant::now();
        assert!(provider.response(&[0; 32]).await.is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(provider.response(&[0; 32]).await.is_err());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn oversized_output_is_not_cached_as_success() {
        let source = source(json!({"data": "x".repeat(2048)}), Duration::ZERO);
        let provider = provider(
            source.clone(),
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        assert!(provider.response(&[0; 32]).await.is_err());
        assert!(provider.response(&[0; 32]).await.is_err());
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn keys_must_match_the_set_read_by_the_attested_verifier() {
        let key = rcgen::KeyPair::generate().unwrap_or_else(|error| panic!("{error:?}"));
        let der = rcgen::PublicKeyData::subject_public_key_info(&key);
        let pem = key.public_key_pem();
        let fingerprint = format!("{:x}", Sha256::digest(&der));
        assert_eq!(
            operator_keys(pem.as_bytes(), &json!({"operator_keys": [fingerprint]}))
                .unwrap_or_else(|error| panic!("{error:?}")),
            vec![pem.clone()]
        );
        assert!(
            operator_keys(pem.as_bytes(), &json!({"operator_keys": ["0".repeat(64)]})).is_err()
        );
        assert!(operator_keys(pem.as_bytes(), &json!({})).is_err());
        assert!(operator_keys(b"", &json!({})).is_err());
        assert!(
            operator_keys(
                b"-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
                &json!({})
            )
            .is_err()
        );
    }

    fn runtime_settings(revision: u64, name: &str) -> Value {
        json!({"schemaVersion":1,"revision":revision,
            "evidence":{"baseUrl":format!("https://{name}.example.test"),"connectHost":"127.0.0.1"},
            "catalogModelIds":["test"],"inferenceModelIds":["test"],"maximumBodyBytes":1024,
            "upstreamTimeoutSeconds":30,"bodyTimeoutSeconds":10,"streamIdleTimeoutSeconds":20,
            "attestationCacheSeconds":30,"globalRequestConcurrency":256,"perAddressConcurrency":16,
            "inferenceConcurrency":1,"inferenceQueue":0,"queueTimeoutSeconds":2,"perKeyConcurrency":4,
            "attestationConcurrency":4,"requestsPerAddressPerSecond":30})
    }

    #[derive(Default)]
    struct RoutingSource {
        calls: AtomicUsize,
        fail: AtomicBool,
        block: AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl MetadataSource for RoutingSource {
        async fn fetch(&self) -> Result<Value, AttestationError> {
            Err(unavailable("missing evidence snapshot"))
        }

        async fn fetch_with_evidence(
            &self,
            endpoint: Option<&EvidenceEndpoint>,
        ) -> Result<Value, AttestationError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let endpoint = endpoint.ok_or_else(|| unavailable("missing evidence snapshot"))?;
            if self.block.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(unavailable("discovery failed"));
            }
            Ok(
                json!({"discovery":endpoint.discovery_url.as_str(),"allowlist":endpoint.allowlist_url.as_str()}),
            )
        }
    }

    #[tokio::test]
    async fn watched_evidence_changes_invalidate_success_and_failure_caches()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{runtime_config::MountedConfig, runtime_settings::GatewaySettings};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&runtime_settings(1, "candidate"))?,
        )?;
        let config = Arc::new(MountedConfig::<GatewaySettings>::open(
            path.clone(),
            4096,
            GatewaySettings::validate,
        )?);
        let watcher = config.watch(GatewaySettings::validate, Duration::from_millis(10));
        let source = Arc::new(RoutingSource::default());
        let provider = MetadataProvider::new(
            source.clone(),
            Duration::from_secs(30),
            Duration::from_secs(2),
            1024,
            Arc::new(GatewayMetrics::new("test")),
        )?
        .with_runtime(Some(config.clone()));
        assert_eq!(
            provider
                .response(&[0; 32])
                .await
                .map_err(|error| format!("{error:?}"))?
                .get("discovery"),
            Some(&json!("https://candidate.example.test/v1/discovery"))
        );
        // Atomic rename exercises the mounted-file watcher, not a reload API.
        for (revision, name) in [
            (2, "api"),
            (3, "broken"),
            (4, "recovered"),
            (6, "candidate"),
            (7, "candidate"),
            (8, "candidate"),
        ] {
            source.fail.store(name == "broken", Ordering::SeqCst);
            let mut settings = runtime_settings(revision, name);
            if revision == 2 || revision == 7 {
                settings["evidence"]["connectHost"] = json!("127.0.0.2");
            }
            if revision == 8 {
                settings["evidence"]
                    .as_object_mut()
                    .ok_or("missing evidence")?
                    .remove("connectHost");
            }
            let next = dir.path().join("next.json");
            std::fs::write(&next, serde_json::to_vec(&settings)?)?;
            std::fs::rename(next, &path)?;
            tokio::time::timeout(Duration::from_secs(2), async {
                while config.status().accepted_revision != revision {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await?;
            let result = provider.response(&[0; 32]).await;
            if name == "broken" {
                assert!(result.is_err());
                continue;
            }
            assert_eq!(
                result.map_err(|error| format!("{error:?}"))?["allowlist"],
                format!("https://{name}.example.test/allowlist")
            );
            if revision == 4 {
                let mut invalid = runtime_settings(5, "bad");
                invalid["evidence"]["baseUrl"] = json!("http://api.example.test");
                std::fs::write(&path, serde_json::to_vec(&invalid)?)?;
                tokio::time::timeout(Duration::from_secs(2), async {
                    while config.status().error.is_none() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await?;
                assert_eq!(config.status().accepted_revision, 4);
                assert_eq!(
                    provider
                        .response(&[0; 32])
                        .await
                        .map_err(|error| format!("{error:?}"))?["allowlist"],
                    "https://recovered.example.test/allowlist"
                );
            }
        }
        assert_eq!(source.calls.load(Ordering::SeqCst), 7);
        watcher.abort();
        Ok(())
    }

    #[tokio::test]
    async fn refresh_in_progress_keeps_old_addresses_and_next_request_uses_new_addresses()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{runtime_config::MountedConfig, runtime_settings::GatewaySettings};
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            serde_json::to_vec(&runtime_settings(1, "candidate"))?,
        )?;
        let config = Arc::new(MountedConfig::<GatewaySettings>::open(
            path.clone(),
            4096,
            GatewaySettings::validate,
        )?);
        let source = Arc::new(RoutingSource::default());
        source.block.store(true, Ordering::SeqCst);
        let provider = Arc::new(
            MetadataProvider::new(
                source.clone(),
                Duration::from_secs(30),
                Duration::from_secs(2),
                1024,
                Arc::new(GatewayMetrics::new("test")),
            )?
            .with_runtime(Some(config.clone())),
        );
        let first = tokio::spawn({
            let provider = provider.clone();
            async move { provider.response(&[0; 32]).await }
        });
        tokio::time::timeout(Duration::from_secs(2), source.entered.notified()).await?;
        std::fs::write(&path, serde_json::to_vec(&runtime_settings(2, "api"))?)?;
        config.refresh(GatewaySettings::validate);
        let second = tokio::spawn({
            let provider = provider.clone();
            async move { provider.response(&[0; 32]).await }
        });
        source.release.notify_one();
        assert_eq!(
            first.await?.map_err(|error| format!("{error:?}"))?["discovery"],
            "https://candidate.example.test/v1/discovery"
        );
        assert_eq!(
            second.await?.map_err(|error| format!("{error:?}"))?["discovery"],
            "https://api.example.test/v1/discovery"
        );
        Ok(())
    }

    #[tokio::test]
    async fn runtime_endpoint_preserves_tls_name_and_refuses_redirects()
    -> Result<(), Box<dyn std::error::Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["candidate.example.test".into()])?;
        let root = reqwest::Certificate::from_der(cert.cert.der())?;
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
            cert.cert.pem().into_bytes(),
            cert.signing_key.serialize_pem().into_bytes(),
        )
        .await?;
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let shutdown = axum_server::Handle::new();
        let task = tokio::spawn(
            axum_server::from_tcp_rustls(listener, tls)
                .handle(shutdown.clone())
                .serve(
                    axum::Router::new()
                        .route(
                            "/v1/discovery",
                            axum::routing::get(|| async {
                                axum::response::Redirect::temporary(
                                    "https://untrusted.example.test/",
                                )
                            }),
                        )
                        .into_make_service(),
                ),
        );
        let settings = EvidenceSettings {
            base_url: format!("https://candidate.example.test:{port}"),
            connect_host: Some("127.0.0.1".into()),
        };
        let good = EvidenceEndpoint::new(
            &settings,
            Duration::from_secs(2),
            std::slice::from_ref(&root),
        )
        .map_err(|error| format!("{error:?}"))?;
        let response = good.client.get(good.discovery_url.clone()).send().await?;
        assert_eq!(response.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        let wrong = EvidenceEndpoint::new(
            &EvidenceSettings {
                base_url: format!("https://api.example.test:{port}"),
                ..settings
            },
            Duration::from_secs(2),
            std::slice::from_ref(&root),
        )
        .map_err(|error| format!("{error:?}"))?;
        assert!(
            wrong
                .client
                .get(wrong.discovery_url.clone())
                .send()
                .await
                .is_err()
        );
        shutdown.shutdown();
        task.await??;
        Ok(())
    }

    fn cds_source(policy: PathBuf, policy_sha256: String) -> CdsMetadataSource {
        CdsMetadataSource {
            cds_url: Url::parse("https://127.0.0.1:1").unwrap_or_else(|error| panic!("{error:?}")),
            discovery_url: Url::parse("https://127.0.0.1:1/.well-known/c8s")
                .unwrap_or_else(|error| panic!("{error:?}")),
            allowlist_url: Url::parse("https://example.test/allowlist")
                .unwrap_or_else(|error| panic!("{error:?}")),
            release_id: "test".into(),
            release_url: Url::parse("https://example.test/release")
                .unwrap_or_else(|error| panic!("{error:?}")),
            bundle_sha256: format!("sha256:{}", "0".repeat(64)),
            verifier: PathBuf::from("/does-not-exist"),
            image_policy: policy.clone(),
            served_image_policy: policy,
            served_image_policy_sha256: policy_sha256.clone(),
            image_policy_sha256: policy_sha256,
            timeout: Duration::from_secs(1),
            maximum_bytes: 1024,
            discovery_client: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn changed_image_policy_is_rejected_before_verifier_or_network_access() {
        let file = tempfile::NamedTempFile::new().unwrap_or_else(|error| panic!("{error:?}"));
        std::fs::write(file.path(), b"changed").unwrap_or_else(|error| panic!("{error:?}"));
        let source = cds_source(file.path().into(), format!("sha256:{}", "0".repeat(64)));
        let error = format!(
            "{:?}",
            source
                .verify_cds()
                .await
                .err()
                .unwrap_or_else(|| panic!("expected failure"))
        );
        assert!(error.contains("hash mismatch"), "{error}");
    }

    #[tokio::test]
    async fn image_policy_read_has_a_byte_limit() {
        let file = tempfile::NamedTempFile::new().unwrap_or_else(|error| panic!("{error:?}"));
        std::fs::write(file.path(), vec![0; 256 * 1024 + 1])
            .unwrap_or_else(|error| panic!("{error:?}"));
        let source = cds_source(file.path().into(), String::new());
        let error = format!(
            "{:?}",
            source
                .verify_cds()
                .await
                .err()
                .unwrap_or_else(|| panic!("expected failure"))
        );
        assert!(error.contains("byte limit"), "{error}");
    }

    #[tokio::test]
    async fn cds_identity_cannot_accept_the_full_agent_policy() {
        let file = tempfile::NamedTempFile::new().unwrap_or_else(|error| panic!("{error:?}"));
        let bytes = br#"{"measurements":[{"name":"server"},{"name":"agent"}]}"#;
        std::fs::write(file.path(), bytes).unwrap_or_else(|error| panic!("{error:?}"));
        let source = cds_source(
            file.path().into(),
            format!("sha256:{:x}", Sha256::digest(bytes)),
        );
        let error = source
            .verify_cds()
            .await
            .err()
            .unwrap_or_else(|| panic!("expected rejection"));
        assert!(
            matches!(error, AttestationError::Unavailable(message) if message.contains("one control-node identity"))
        );
    }
}
