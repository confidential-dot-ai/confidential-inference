//! Public policy metadata. Only CDS and C8s discovery are upstream sources.

use crate::{AttestationError, AttestationProvider, metrics::GatewayMetrics};
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
}

/// A short successful cache and a short failure cooldown bound CDS load.
/// The same mutex serializes refreshes. Expired documents are never returned.
pub struct MetadataProvider {
    source: Arc<dyn MetadataSource>,
    cache: Mutex<Option<(Instant, Result<Value, AttestationError>)>>,
    ttl: Duration,
    timeout: Duration,
    maximum_bytes: usize,
    metrics: Arc<GatewayMetrics>,
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
            cache: Mutex::new(None),
            ttl,
            timeout,
            maximum_bytes,
            metrics,
        })
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
        if let Some((expires, result)) = &*cache
            && *expires > Instant::now()
        {
            self.metrics.record_attestation_event(if result.is_ok() {
                "cache_hit"
            } else {
                "failure_cooldown"
            });
            return result.clone();
        }
        self.metrics.record_attestation_event("cache_miss");
        let result = match tokio::time::timeout(self.timeout, self.source.fetch()).await {
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
        let lifetime = if result.is_ok() {
            self.ttl
        } else {
            Duration::from_secs(1)
        };
        *cache = Some((Instant::now() + lifetime, result.clone()));
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
            self.discovery_client.get(self.discovery_url.clone()).send()
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
                        "url": self.allowlist_url.as_str()}, "discovery": discovery, "operatorKeys": keys}}))
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
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let mut der =
            hex::decode("302a300506032b6570032100").unwrap_or_else(|error| panic!("{error:?}"));
        der.extend_from_slice(signing.verifying_key().as_bytes());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(&der)
        );
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
