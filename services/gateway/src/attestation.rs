//! The fail-closed c8s evidence collector.

use std::{
    io::{BufReader, Cursor},
    time::Duration,
};

use base64::Engine as _;
use futures_util::StreamExt as _;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use url::Url;
use x509_parser::{
    prelude::{FromDer, SubjectPublicKeyInfo},
    public_key::PublicKey,
};

use crate::{AttestationError, AttestationProvider};

const MAX_METADATA_BYTES: usize = 1_048_576;
const OPERATOR_KEY_SET_DOMAIN: &[u8] = b"c8s-operator-key-set-v1\0";
const MAX_OPERATOR_KEY_SET_BYTES: usize = 256 * 1_024;

#[derive(Clone, Debug)]
struct OperatorKeySet {
    raw_pem: String,
    canonical_pem: String,
    digest: String,
    c8s_digest: String,
    fingerprints: Vec<String>,
}

#[derive(Clone, Debug)]
struct ReceiptTarget {
    target: String,
    /// Exact allowlist entry selected by c8s admission.
    workload: String,
    /// Stable workload identity declared by that allowlist entry.
    identity: String,
    base_url: Url,
}

struct CollectedEvidence {
    receipts: Vec<Value>,
    mesh_ca_sha256: String,
    operator_keys: Option<OperatorKeySet>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PolicyMode {
    Operator,
    Static,
}

/// Static inputs for one release and its c8s evidence endpoints.
#[derive(Clone, Copy)]
pub struct C8sAttestationConfig<'a> {
    pub targets: &'a str,
    pub evidence_base_url: &'a str,
    pub release_id: &'a str,
    pub release_bundle_sha256: &'a str,
    pub expected_operator_public_key_sha256: &'a str,
    /// c8s operator key-set commitment. This is distinct from one key's SPKI digest.
    pub expected_operator_key_set_sha256: &'a str,
    /// Policy source. `operator` supports signed updates. `static` is sealed
    /// into the measured node image and has no update key.
    pub policy_mode: &'a str,
    /// Canonical allowlist digest required in static mode.
    pub expected_static_allowlist_sha256: &'a str,
    pub timeout: Duration,
    pub maximum_receipt_bytes: usize,
}

#[derive(Clone)]
pub struct C8sAttestationProvider {
    http: reqwest::Client,
    targets: Vec<ReceiptTarget>,
    evidence_base_url: Url,
    release_id: String,
    release_bundle_sha256: String,
    expected_operator_public_key_sha256: String,
    expected_operator_key_set_sha256: String,
    policy_mode: PolicyMode,
    expected_static_allowlist_sha256: String,
    maximum_receipt_bytes: usize,
}

impl C8sAttestationProvider {
    /// Build a collector for one exact environment workload set.
    ///
    /// # Errors
    ///
    /// This function rejects missing, duplicate, or malformed inputs.
    pub fn from_config(config: C8sAttestationConfig<'_>) -> Result<Self, String> {
        if config.timeout.is_zero() || config.timeout > Duration::from_secs(120) {
            return Err("the c8s receipt timeout is invalid".to_owned());
        }
        if !(64 * 1_024..=8 * 1_024 * 1_024).contains(&config.maximum_receipt_bytes) {
            return Err("the c8s receipt size limit is invalid".to_owned());
        }
        if !safe_release_id(config.release_id) {
            return Err("the release identifier is invalid".to_owned());
        }
        if !valid_sha256_digest(config.release_bundle_sha256) {
            return Err("the release bundle digest is invalid".to_owned());
        }
        let policy_mode = match config.policy_mode {
            "operator" => PolicyMode::Operator,
            "static" => PolicyMode::Static,
            _ => return Err("the c8s policy mode must be operator or static".to_owned()),
        };
        match policy_mode {
            PolicyMode::Operator => {
                if !valid_sha256_digest(config.expected_operator_public_key_sha256) {
                    return Err("the expected operator public key digest is invalid".to_owned());
                }
                if !valid_sha256_digest(config.expected_operator_key_set_sha256) {
                    return Err("the expected operator key set digest is invalid".to_owned());
                }
            }
            PolicyMode::Static => {
                if !valid_sha256_digest(config.expected_static_allowlist_sha256) {
                    return Err("the expected static allowlist digest is invalid".to_owned());
                }
            }
        }
        let evidence_base_url = parse_evidence_base_url(config.evidence_base_url)?;
        let targets = parse_targets(config.targets)?;
        // When the front door terminates TLS in cds mode, its serving
        // certificate is issued by the cluster's own mesh CA — WebPKI cannot
        // verify it. Every c8s workload pod carries that CA at
        // /etc/c8s/certs/ca.crt (minted by the get-cert init), so trust it for
        // the evidence fetch. WebPKI front doors keep working unchanged: this
        // only ADDS a root, it never replaces the platform roots.
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(config.timeout.min(Duration::from_secs(10)))
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none());
        if let Ok(mesh_ca_pem) = std::fs::read("/etc/c8s/certs/ca.crt") {
            let mut added = 0usize;
            let mut rest: &[u8] = &mesh_ca_pem;
            while !rest.is_empty() {
                let (remaining, pem) = x509_parser::pem::parse_x509_pem(rest)
                    .map_err(|_| "the c8s mesh CA bundle is invalid".to_owned())?;
                let cert = reqwest::Certificate::from_der(&pem.contents)
                    .map_err(|_| "the c8s mesh CA certificate is invalid".to_owned())?;
                client_builder = client_builder.add_root_certificate(cert);
                added += 1;
                rest = remaining;
            }
            if added == 0 {
                return Err("the c8s mesh CA bundle is empty".to_owned());
            }
        }
        let http = client_builder
            .build()
            .map_err(|_| "the c8s evidence HTTP client is invalid".to_owned())?;
        Ok(Self {
            http,
            targets,
            evidence_base_url,
            release_id: config.release_id.to_owned(),
            release_bundle_sha256: config.release_bundle_sha256.to_owned(),
            expected_operator_public_key_sha256: config
                .expected_operator_public_key_sha256
                .to_owned(),
            expected_operator_key_set_sha256: config.expected_operator_key_set_sha256.to_owned(),
            policy_mode,
            expected_static_allowlist_sha256: config.expected_static_allowlist_sha256.to_owned(),
            maximum_receipt_bytes: config.maximum_receipt_bytes,
        })
    }

    async fn fetch_receipt(
        &self,
        target: &ReceiptTarget,
        nonce: &str,
    ) -> Result<Value, AttestationError> {
        let ready_url = target
            .base_url
            .join("readyz")
            .map_err(|_| AttestationError::Invalid)?;
        let ready = self
            .http
            .get(ready_url)
            .send()
            .await
            .map_err(|_| AttestationError::Unavailable)?;
        if !ready.status().is_success() {
            return Err(AttestationError::Unavailable);
        }
        read_bounded(ready, 4_096).await?;

        let mut receipt_url = target
            .base_url
            .join(".well-known/c8s/attest-pq")
            .map_err(|_| AttestationError::Invalid)?;
        receipt_url.query_pairs_mut().append_pair("nonce", nonce);
        let response = self
            .http
            .get(receipt_url)
            .send()
            .await
            .map_err(|_| AttestationError::Unavailable)?;
        require_success(&response)?;
        let body = read_bounded(response, self.maximum_receipt_bytes).await?;
        let receipt: Value =
            serde_json::from_slice(&body).map_err(|_| AttestationError::Invalid)?;
        validate_standard_receipt(&receipt, nonce, "c8s/attest-pq/v1")?;
        Ok(receipt)
    }

    async fn fetch_front_door_receipt(&self, nonce: &str) -> Result<Value, AttestationError> {
        let mut url = self
            .evidence_base_url
            .join(".well-known/c8s/attest-lb")
            .map_err(|_| AttestationError::Invalid)?;
        url.query_pairs_mut().append_pair("nonce", nonce);
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| AttestationError::Unavailable)?;
        require_success(&response)?;
        let body = read_bounded(response, self.maximum_receipt_bytes).await?;
        let receipt: Value =
            serde_json::from_slice(&body).map_err(|_| AttestationError::Invalid)?;
        validate_standard_receipt(&receipt, nonce, "c8s/attest-lb/v1")?;
        Ok(receipt)
    }

    async fn fetch_json(
        &self,
        path: &str,
        limit: usize,
    ) -> Result<(Value, Vec<u8>), AttestationError> {
        let url = self
            .evidence_base_url
            .join(path)
            .map_err(|_| AttestationError::Invalid)?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| AttestationError::Unavailable)?;
        require_success(&response)?;
        let bytes = read_bounded(response, limit).await?;
        let document = serde_json::from_slice(&bytes).map_err(|_| AttestationError::Invalid)?;
        Ok((document, bytes))
    }

    async fn collect_workload_evidence(
        &self,
        allowlist: &Value,
        nonce: &str,
    ) -> Result<CollectedEvidence, AttestationError> {
        let mut receipts = Vec::with_capacity(self.targets.len());
        let mut mesh_ca_sha256 = None;
        let mut operator_keys: Option<OperatorKeySet> = None;
        for target in &self.targets {
            let identity = policy_identity(allowlist, &target.workload)?;
            if identity != target.identity {
                return Err(AttestationError::Invalid);
            }
            let receipt = self.fetch_receipt(target, nonce).await?;
            if self.policy_mode == PolicyMode::Operator {
                let receipt_operator_keys = receipt_operator_key_set(&receipt)?;
                if let Some(expected) = &operator_keys {
                    require_matching_operator_keys(expected, &receipt_operator_keys)?;
                } else {
                    operator_keys = Some(receipt_operator_keys);
                }
            }
            let receipt_mesh_ca = receipt_mesh_ca_sha256(&receipt)?;
            require_matching_mesh_ca(mesh_ca_sha256.as_deref(), &receipt_mesh_ca)?;
            mesh_ca_sha256.get_or_insert(receipt_mesh_ca);
            receipts.push(json!({
                "target": target.target,
                "workload": target.workload,
                "identity": identity,
                "admittedLaunch": admitted_launch(allowlist, &target.workload)?,
                "receipt": receipt,
            }));
        }
        Ok(CollectedEvidence {
            receipts,
            mesh_ca_sha256: mesh_ca_sha256.ok_or(AttestationError::Invalid)?,
            operator_keys,
        })
    }

    async fn collect_front_door_evidence(
        &self,
        nonce: &str,
        tls_mode: &str,
        evidence: &CollectedEvidence,
    ) -> Result<Option<Value>, AttestationError> {
        if !matches!(tls_mode, "cds" | "acme" | "tee-webpki") {
            return Ok(None);
        }
        let receipt = self.fetch_front_door_receipt(nonce).await?;
        if self.policy_mode == PolicyMode::Operator {
            let receipt_operator_keys = receipt_operator_key_set(&receipt)?;
            require_matching_operator_keys(
                evidence
                    .operator_keys
                    .as_ref()
                    .ok_or(AttestationError::Invalid)?,
                &receipt_operator_keys,
            )?;
        }
        let receipt_mesh_ca = receipt_mesh_ca_sha256(&receipt)?;
        require_matching_mesh_ca(Some(&evidence.mesh_ca_sha256), &receipt_mesh_ca)?;
        Ok(Some(json!({"source": "c8s-tls-lb", "receipt": receipt})))
    }
}

#[async_trait::async_trait]
impl AttestationProvider for C8sAttestationProvider {
    async fn response(&self, nonce: &[u8; 32]) -> Result<Value, AttestationError> {
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let (discovery_result, allowlist_result) = tokio::join!(
            self.fetch_json("v1/discovery", MAX_METADATA_BYTES),
            self.fetch_json("allowlist", self.maximum_receipt_bytes),
        );
        let (discovery, _) = discovery_result?;
        validate_discovery(&discovery)?;
        let (allowlist, allowlist_bytes) = allowlist_result?;
        let canonical_allowlist = validate_allowlist(&allowlist, &allowlist_bytes)?;
        let tls_mode = discovery
            .pointer("/public_tls/mode")
            .and_then(Value::as_str)
            .ok_or(AttestationError::Invalid)?;

        let active_allowlist_sha256 = sha256_digest(&canonical_allowlist);
        if self.policy_mode == PolicyMode::Static
            && active_allowlist_sha256 != self.expected_static_allowlist_sha256
        {
            return Err(AttestationError::Invalid);
        }
        let evidence = self.collect_workload_evidence(&allowlist, &nonce).await?;
        let front_door = self
            .collect_front_door_evidence(&nonce, tls_mode, &evidence)
            .await?;
        if self.policy_mode == PolicyMode::Operator {
            let operator_keys = evidence
                .operator_keys
                .as_ref()
                .ok_or(AttestationError::Invalid)?;
            if operator_keys.digest != self.expected_operator_key_set_sha256
                || !operator_keys
                    .fingerprints
                    .iter()
                    .any(|fingerprint| fingerprint == &self.expected_operator_public_key_sha256)
            {
                return Err(AttestationError::Invalid);
            }
        }

        let policy_trust = match self.policy_mode {
            PolicyMode::Static => json!({
                "mode": "static",
                "expectedAllowlistSha256": self.expected_static_allowlist_sha256,
                "activeAllowlistSha256": active_allowlist_sha256,
                "status": "evidence-present-requires-independent-verification",
                "reason": "verify the sealed allowlist extension and embedded TEE evidence in the returned mesh CA chain",
            }),
            PolicyMode::Operator => {
                let operator_keys = evidence
                    .operator_keys
                    .as_ref()
                    .ok_or(AttestationError::Invalid)?;
                json!({
                    "mode": "operator",
                    "expectedPublicKeySpkiSha256": self.expected_operator_public_key_sha256,
                    "expectedKeySetSha256": self.expected_operator_key_set_sha256,
                    "activeKeySetSha256": operator_keys.digest,
                    "activeKeySetPem": operator_keys.canonical_pem,
                    "activeKeySetC8sSha256": operator_keys.c8s_digest,
                    "status": "evidence-present-and-release-matched",
                    "reason": "the active operator key set was copied from every nonce-bound c8s receipt and matched the release commitment",
                })
            }
        };

        Ok(json!({
            "schemaVersion": 2,
            "scope": "launch-or-admission-only",
            "nonce": nonce,
            "operationalStatus": "not-verified",
            "release": {
                "id": self.release_id,
                "bundleSha256": self.release_bundle_sha256,
                "source": "operator-selected-public-release",
            },
            "c8s": {
                "discovery": discovery,
                "activeAllowlist": {
                    "sha256": active_allowlist_sha256,
                    "document": allowlist,
                },
                "policyTrust": policy_trust,
                "meshCaSha256": evidence.mesh_ca_sha256,
            },
            "tls": {"mode": tls_mode, "binding": tls_binding(tls_mode)},
            "frontDoor": front_door,
            "gpuEvidence": gpu_evidence(&evidence.receipts),
            "receipts": evidence.receipts,
        }))
    }
}

fn require_matching_operator_keys(
    expected: &OperatorKeySet,
    actual: &OperatorKeySet,
) -> Result<(), AttestationError> {
    if expected.raw_pem == actual.raw_pem && expected.digest == actual.digest {
        Ok(())
    } else {
        Err(AttestationError::Invalid)
    }
}

fn require_matching_mesh_ca(expected: Option<&str>, actual: &str) -> Result<(), AttestationError> {
    if expected.is_none_or(|value| value == actual) {
        Ok(())
    } else {
        Err(AttestationError::Invalid)
    }
}

fn tls_binding(tls_mode: &str) -> Value {
    if tls_mode == "webpki" {
        json!({
            "status": "not-proven",
            "publicKeySha256": null,
            "reason": "c8s attest-lb rejects a WebPKI key supplied through Kubernetes",
        })
    } else if matches!(tls_mode, "acme" | "tee-webpki") {
        json!({
            "status": "requires-attest-lb",
            "publicKeySha256": null,
            "reason": "c8s holds the public TLS key inside the TEE; TLS-LB evidence is required to verify the exact serving certificate",
        })
    } else {
        json!({
            "status": "requires-attest-lb",
            "publicKeySha256": null,
            "reason": "the workload receipts use attest-pq and do not bind the outer TLS key",
        })
    }
}

fn gpu_evidence(receipts: &[Value]) -> Value {
    let evidence = receipts
        .iter()
        .filter_map(|item| {
            item.get("receipt").and_then(|receipt| {
                receipt.get("nvidia_gpu").map(|gpu| {
                    json!({
                        "target": item.get("target"),
                        "workload": item.get("workload"),
                        "gpuAttested": receipt.get("gpu_attested"),
                        "reportData": receipt.pointer("/evidence/report_data"),
                        "nvidiaGpu": gpu,
                    })
                })
            })
        })
        .collect::<Vec<_>>();
    json!({
        "status": "raw-receipt-evidence",
        "evidence": evidence,
        "reason": "raw NVIDIA evidence is copied from worker receipts; cryptographic GPU verification remains a c8s verifier dependency",
    })
}

fn require_success(response: &reqwest::Response) -> Result<(), AttestationError> {
    if response.status().is_success() {
        Ok(())
    } else if response.status().is_server_error() {
        Err(AttestationError::Unavailable)
    } else {
        Err(AttestationError::Invalid)
    }
}

fn parse_targets(targets: &str) -> Result<Vec<ReceiptTarget>, String> {
    let mut parsed = Vec::new();
    for entry in targets.split(',') {
        let (identity, raw_url) = entry
            .split_once('=')
            .ok_or_else(|| "a c8s receipt target is malformed".to_owned())?;
        let mut fields = identity.split('|');
        let (Some(target), Some(workload), Some(stable_identity), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err("a c8s receipt target lacks its policy and stable identity".to_owned());
        };
        if !safe_name(target) || !safe_name(workload) || !safe_name(stable_identity) {
            return Err("a c8s receipt target, policy, or stable identity is invalid".to_owned());
        }
        if parsed
            .iter()
            .any(|item: &ReceiptTarget| item.target == target)
        {
            return Err(format!("the c8s receipt target {target} is duplicated"));
        }
        let url = Url::parse(raw_url)
            .map_err(|_| format!("the c8s receipt URL for {target} is invalid"))?;
        if url.scheme() != "http"
            || url.host_str().is_none()
            || url.port().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || (url.path() != "" && url.path() != "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(format!("the c8s receipt URL for {target} is unsafe"));
        }
        parsed.push(ReceiptTarget {
            target: target.to_owned(),
            workload: workload.to_owned(),
            identity: stable_identity.to_owned(),
            base_url: url,
        });
    }
    if parsed.is_empty() || parsed.len() > 64 {
        return Err("the c8s receipt target count is invalid".to_owned());
    }
    parsed.sort_by(|left, right| left.target.cmp(&right.target));
    Ok(parsed)
}

fn parse_evidence_base_url(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "the c8s evidence URL is invalid".to_owned())?;
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost"));
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || (url.path() != "" && url.path() != "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("the c8s evidence URL is unsafe".to_owned());
    }
    Ok(url)
}

fn validate_discovery(value: &Value) -> Result<(), AttestationError> {
    if value.get("version").and_then(Value::as_str) != Some("v1")
        || value.get("generated_at").and_then(Value::as_str).is_none()
        || value
            .pointer("/public_tls/hostname")
            .and_then(Value::as_str)
            .is_none()
        || !matches!(
            value.pointer("/public_tls/mode").and_then(Value::as_str),
            Some("webpki" | "cds" | "acme" | "tee-webpki")
        )
        || value
            .pointer("/cds_tls/certificate_pem")
            .and_then(Value::as_str)
            .is_none()
        || value
            .pointer("/cds_tls/certificate_sha256")
            .and_then(Value::as_str)
            .is_none()
        || value
            .pointer("/attestation/platform")
            .and_then(Value::as_str)
            .is_none()
        || !value
            .pointer("/attestation/evidence")
            .is_some_and(Value::is_object)
    {
        return Err(AttestationError::Invalid);
    }
    Ok(())
}

/// Parse and commit to c8s's canonical operator public-key set.
///
/// c8s hashes each PKIX/SPKI DER key, sorts and de-duplicates those hashes,
/// then hashes the domain separator and the resulting hashes. The PEM text is
/// only a transport format and is canonicalized before it is returned.
fn canonical_operator_key_set(bytes: &[u8]) -> Result<OperatorKeySet, AttestationError> {
    if bytes.is_empty() || bytes.len() > MAX_OPERATOR_KEY_SET_BYTES {
        return Err(AttestationError::Invalid);
    }
    let mut reader = BufReader::new(bytes);
    let items = rustls_pemfile::read_all(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AttestationError::Invalid)?;
    let mut ders = Vec::<Vec<u8>>::new();
    for item in items {
        let der = match item {
            rustls_pemfile::Item::SubjectPublicKeyInfo(key) => key.as_ref().to_vec(),
            // c8s ignores other PEM blocks. In particular, do not copy a
            // certificate or private-key block into the public policy.
            _ => continue,
        };
        let (remaining, spki) =
            SubjectPublicKeyInfo::from_der(&der).map_err(|_| AttestationError::Invalid)?;
        if !remaining.is_empty() || !matches!(spki.parsed(), Ok(PublicKey::EC(_))) {
            return Err(AttestationError::Invalid);
        }
        ders.push(der);
    }
    if ders.is_empty() {
        return Err(AttestationError::Invalid);
    }

    let mut fingerprints = ders
        .iter()
        .map(|der| Sha256::digest(der).to_vec())
        .collect::<Vec<_>>();
    fingerprints.sort();
    fingerprints.dedup();
    let mut commitment = Sha256::new();
    commitment.update(OPERATOR_KEY_SET_DOMAIN);
    for fingerprint in &fingerprints {
        commitment.update(fingerprint);
    }

    // Sort the public PEM output by the same fingerprint order. This makes
    // the raw evidence stable across c8s and gateway implementations.
    let mut indexed = ders
        .into_iter()
        .map(|der| (Sha256::digest(&der).to_vec(), der))
        .collect::<Vec<_>>();
    indexed.sort_by(|left, right| left.0.cmp(&right.0));
    indexed.dedup_by(|left, right| left.0 == right.0);
    let canonical_pem = indexed
        .iter()
        .map(|(_, der)| pem_public_key(der))
        .collect::<String>();
    let digest_bytes = commitment.finalize();
    let digest_hex = hex::encode(digest_bytes);
    Ok(OperatorKeySet {
        raw_pem: String::from_utf8(bytes.to_vec()).map_err(|_| AttestationError::Invalid)?,
        canonical_pem,
        digest: format!("sha256:{digest_hex}"),
        c8s_digest: digest_hex,
        fingerprints: fingerprints
            .into_iter()
            .map(|fingerprint| format!("sha256:{}", hex::encode(fingerprint)))
            .collect(),
    })
}

fn receipt_operator_key_set(receipt: &Value) -> Result<OperatorKeySet, AttestationError> {
    let pem = receipt
        .get("operator_keys_pem")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= MAX_OPERATOR_KEY_SET_BYTES)
        .ok_or(AttestationError::Invalid)?;
    let c8s_digest = receipt
        .get("operator_keys_sha256")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or(AttestationError::Invalid)?;
    let mut policy = canonical_operator_key_set(pem.as_bytes())?;
    if policy.c8s_digest != c8s_digest {
        return Err(AttestationError::Invalid);
    }
    pem.clone_into(&mut policy.raw_pem);
    Ok(policy)
}

fn pem_public_key(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // STANDARD encoding only emits ASCII.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn validate_allowlist(value: &Value, bytes: &[u8]) -> Result<Vec<u8>, AttestationError> {
    if value.get("schema").and_then(Value::as_str) != Some("c8s.allowlist/v1")
        || !value.get("workloads").is_some_and(Value::is_object)
    {
        return Err(AttestationError::Invalid);
    }
    // c8s serves the allowlist in two shapes. The branch this gateway was
    // built against (c8s 079aeb48, goal/production-attestation) serves a
    // top-level "digests" floor map. c8s main (#551) folded the floor
    // digests into per-workload entries and serves no "digests" key. Accept
    // either: a present "digests" must still be an object, and an absent one
    // is only valid when every container in every workload entry pins an
    // image digest, which is the floor data at its main-line location. CDS
    // enforces the per-container digest at ingest in both versions, so the
    // folded check rejects only documents no real CDS would serve.
    match value.get("digests") {
        Some(digests) => {
            if !digests.is_object() {
                return Err(AttestationError::Invalid);
            }
        }
        None => validate_folded_workload_digests(value)?,
    }
    // CDS returns the exact bytes from c8s Allowlist.Canonical(). Do not
    // re-serialize the parsed object here. serde_json uses a different object
    // key order, which changes the policy digest. A source-controlled
    // allowlist may contain one final newline; CDS does not return it.
    let canonical = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if canonical.is_empty()
        || canonical.first() != Some(&b'{')
        || canonical.last() != Some(&b'}')
        || canonical.contains(&b'\n')
        || canonical.contains(&b'\r')
    {
        return Err(AttestationError::Invalid);
    }
    Ok(canonical.to_vec())
}

/// Require the folded digest floor of a c8s main-line allowlist: after c8s
/// #551 the document carries no top-level "digests" map, so every image
/// digest the floor admitted must instead appear as a digest pin on a
/// container in a workload entry. A container list that is null or absent
/// carries no containers to check; Go serves an empty slice as either.
fn validate_folded_workload_digests(value: &Value) -> Result<(), AttestationError> {
    let workloads = value
        .get("workloads")
        .and_then(Value::as_object)
        .ok_or(AttestationError::Invalid)?;
    for entry in workloads.values() {
        let entry = entry.as_object().ok_or(AttestationError::Invalid)?;
        for key in ["initContainers", "containers"] {
            let Some(list) = entry.get(key) else {
                continue;
            };
            let Some(containers) = list.as_array() else {
                if list.is_null() {
                    continue;
                }
                return Err(AttestationError::Invalid);
            };
            for container in containers {
                let digest = container
                    .get("digest")
                    .and_then(Value::as_str)
                    .ok_or(AttestationError::Invalid)?;
                if !valid_sha256_digest(digest) {
                    return Err(AttestationError::Invalid);
                }
            }
        }
    }
    Ok(())
}

fn admitted_launch(allowlist: &Value, workload: &str) -> Result<Value, AttestationError> {
    let policy = allowlist
        .pointer(&format!("/workloads/{}", escape_pointer(workload)))
        .and_then(Value::as_object)
        .ok_or(AttestationError::Invalid)?;
    let init_containers = policy
        .get("initContainers")
        .and_then(Value::as_array)
        .ok_or(AttestationError::Invalid)?;
    let containers = policy
        .get("containers")
        .and_then(Value::as_array)
        .ok_or(AttestationError::Invalid)?;
    if containers.is_empty() {
        return Err(AttestationError::Invalid);
    }
    let init_launches = init_containers
        .iter()
        .map(exact_container_launch)
        .collect::<Result<Vec<_>, _>>()?;
    let launches = containers
        .iter()
        .map(exact_container_launch)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "policyName": workload,
        "initContainers": init_launches,
        "containers": launches,
    }))
}

fn policy_identity(allowlist: &Value, workload: &str) -> Result<String, AttestationError> {
    let policy = allowlist
        .pointer(&format!("/workloads/{}", escape_pointer(workload)))
        .and_then(Value::as_object)
        .ok_or(AttestationError::Invalid)?;
    let identity = policy
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or(workload);
    if !safe_name(identity) {
        return Err(AttestationError::Invalid);
    }
    Ok(identity.to_owned())
}

fn exact_container_launch(container: &Value) -> Result<Value, AttestationError> {
    let object = container.as_object().ok_or(AttestationError::Invalid)?;
    let image = object
        .get("image")
        .and_then(Value::as_str)
        .ok_or(AttestationError::Invalid)?;
    let digest = object
        .get("digest")
        .and_then(Value::as_str)
        .filter(|value| valid_sha256_digest(value))
        .ok_or(AttestationError::Invalid)?;
    if !image.ends_with(digest) {
        return Err(AttestationError::Invalid);
    }
    let mut argv = exact_argv(object.get("command"), false)?;
    argv.extend(exact_argv(object.get("args"), true)?);
    Ok(json!({"image": image, "digest": digest, "argv": argv}))
}

fn exact_argv(value: Option<&Value>, allow_deny: bool) -> Result<Vec<String>, AttestationError> {
    let policy = value
        .and_then(Value::as_object)
        .ok_or(AttestationError::Invalid)?;
    let name = policy
        .get("policy")
        .and_then(Value::as_str)
        .ok_or(AttestationError::Invalid)?;
    if name == "deny" && allow_deny {
        return Ok(Vec::new());
    }
    if name != "exact" {
        return Err(AttestationError::Invalid);
    }
    let argv = policy
        .get("argv")
        .and_then(Value::as_array)
        .ok_or(AttestationError::Invalid)?;
    if argv.is_empty() {
        return Err(AttestationError::Invalid);
    }
    argv.iter()
        .map(|item| {
            item.as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or(AttestationError::Invalid)
        })
        .collect()
}

fn receipt_mesh_ca_sha256(receipt: &Value) -> Result<String, AttestationError> {
    let encoded = receipt
        .pointer("/identity_proof/mesh_ca_sha256")
        .and_then(Value::as_str)
        .ok_or(AttestationError::Invalid)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AttestationError::Invalid)?;
    if decoded.len() != 32 {
        return Err(AttestationError::Invalid);
    }
    Ok(format!("sha256:{}", hex::encode(decoded)))
}

fn escape_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}
fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

fn safe_release_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

async fn read_bounded(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, AttestationError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(AttestationError::Invalid);
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AttestationError::Unavailable)?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(AttestationError::Invalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_standard_receipt(
    receipt: &Value,
    nonce: &str,
    expected_version: &str,
) -> Result<(), AttestationError> {
    let object = receipt.as_object().ok_or(AttestationError::Invalid)?;
    if object.get("version").and_then(Value::as_str) != Some(expected_version)
        || object.get("platform").and_then(Value::as_str) != Some("tdx")
        || object.get("nonce").and_then(Value::as_str) != Some(nonce)
        || !object.get("evidence").is_some_and(Value::is_object)
    {
        return Err(AttestationError::Invalid);
    }
    let certificate = object
        .get("cds_cert_pem")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= 256 * 1_024)
        .ok_or(AttestationError::Invalid)?;
    let mut reader = Cursor::new(certificate.as_bytes());
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AttestationError::Invalid)?;
    if certificates.len() < 2 {
        return Err(AttestationError::Invalid);
    }

    if expected_version == "c8s/attest-pq/v1" {
        let session = object
            .get("session_pubkey")
            .and_then(Value::as_object)
            .ok_or(AttestationError::Invalid)?;
        decode_exact(session.get("x25519"), 32)?;
        decode_exact(session.get("mlkem768"), 1_184)?;
    } else if expected_version == "c8s/attest-lb/v1" {
        decode_exact(object.get("serving_leaf_sha256"), 32)?;
    }
    let proof = object
        .get("identity_proof")
        .and_then(Value::as_object)
        .ok_or(AttestationError::Invalid)?;
    if proof.get("algorithm").and_then(Value::as_str) != Some("ecdsa-sha384") {
        return Err(AttestationError::Invalid);
    }
    decode_exact(proof.get("leaf_sha256"), 32)?;
    decode_exact(proof.get("mesh_ca_sha256"), 32)?;
    let signature = proof
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(AttestationError::Invalid)?;
    let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AttestationError::Invalid)?;
    if signature_bytes.is_empty()
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature_bytes) != signature
    {
        return Err(AttestationError::Invalid);
    }
    Ok(())
}

fn decode_exact(value: Option<&Value>, length: usize) -> Result<(), AttestationError> {
    let encoded = value
        .and_then(Value::as_str)
        .ok_or(AttestationError::Invalid)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AttestationError::Invalid)?;
    if decoded.len() != length
        || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(decoded) != encoded
    {
        return Err(AttestationError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_exact_c8s_allowlist_byte_order() {
        let source = include_bytes!("../../../c8s/allowlists/staging.json");
        let Ok(value) = serde_json::from_slice::<Value>(source) else {
            panic!("the public allowlist test fixture must contain JSON");
        };
        let Ok(canonical) = validate_allowlist(&value, source) else {
            panic!("the public allowlist test fixture must use canonical c8s bytes");
        };
        assert_eq!(
            canonical.as_slice(),
            source.strip_suffix(b"\n").unwrap_or(source)
        );

        let Ok(rust_reserialized) = serde_json::to_vec(&value) else {
            panic!("the parsed JSON test fixture must serialize");
        };
        assert_ne!(
            canonical, rust_reserialized,
            "the regression fixture must expose the key-order difference"
        );
    }

    /// The c8s main-line (#551) document shape: no top-level "digests" map.
    /// The first entry is a folded floor digest (unconstrained argv); the
    /// second pins an exact launch.
    fn main_line_allowlist() -> Value {
        let floor_digest = format!("sha256:{}", "a".repeat(64));
        let pinned_digest = format!("sha256:{}", "b".repeat(64));
        json!({
            "schema": "c8s.allowlist/v1",
            "workloads": {
                "cds-3f2a9c8b1e2f": {
                    "label": format!("ghcr.io/confidential-dot-ai/cds@{floor_digest}"),
                    "initContainers": [],
                    "containers": [{
                        "digest": floor_digest,
                        "image": format!("ghcr.io/confidential-dot-ai/cds@{floor_digest}"),
                        "command": {"policy": "any"},
                        "args": {"policy": "any"},
                    }],
                },
                "vllm-llama": {
                    "label": "docker.io/vllm/vllm-openai:v0.6.3",
                    "initContainers": [],
                    "containers": [{
                        "digest": pinned_digest,
                        "image": format!("docker.io/vllm/vllm-openai@{pinned_digest}"),
                        "command": {"policy": "exact", "argv": ["python3"]},
                        "args": {"policy": "exact", "argv": ["-m", "vllm.entrypoints.openai.api_server"]},
                    }],
                },
            }
        })
    }

    fn canonical_bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn keeps_accepting_the_branch_allowlist_shape() {
        let value = json!({"schema": "c8s.allowlist/v1", "digests": {}, "workloads": {}});
        let bytes = canonical_bytes(&value);
        let Ok(canonical) = validate_allowlist(&value, &bytes) else {
            panic!("the branch allowlist shape must stay accepted");
        };
        assert_eq!(canonical, bytes);
    }

    #[test]
    fn rejects_a_non_object_digests_field() {
        for digests in [json!([]), json!(null), json!("floor")] {
            let value = json!({"schema": "c8s.allowlist/v1", "digests": digests, "workloads": {}});
            assert!(validate_allowlist(&value, &canonical_bytes(&value)).is_err());
        }
    }

    #[test]
    fn accepts_the_c8s_main_line_allowlist_shape() {
        let value = main_line_allowlist();
        let bytes = canonical_bytes(&value);
        let Ok(canonical) = validate_allowlist(&value, &bytes) else {
            panic!("the c8s main-line allowlist shape must be accepted");
        };
        assert_eq!(canonical, bytes);

        // Go serves an empty container slice as either [] or null.
        let mut nulled = main_line_allowlist();
        nulled["workloads"]["vllm-llama"]["initContainers"] = json!(null);
        let bytes = canonical_bytes(&nulled);
        assert!(validate_allowlist(&nulled, &bytes).is_ok());
    }

    #[test]
    fn rejects_a_main_line_container_without_a_digest_pin() {
        let mut missing = main_line_allowlist();
        missing["workloads"]["vllm-llama"]["containers"][0]
            .as_object_mut()
            .unwrap_or_else(|| unreachable!())
            .remove("digest");
        assert!(validate_allowlist(&missing, &canonical_bytes(&missing)).is_err());

        let mut malformed = main_line_allowlist();
        malformed["workloads"]["cds-3f2a9c8b1e2f"]["containers"][0]["digest"] =
            json!("sha256:not-hex");
        assert!(validate_allowlist(&malformed, &canonical_bytes(&malformed)).is_err());
    }

    #[test]
    fn rejects_a_main_line_container_list_that_is_not_an_array() {
        let mut value = main_line_allowlist();
        value["workloads"]["vllm-llama"]["containers"] = json!({"digest": "sha256:abc"});
        assert!(validate_allowlist(&value, &canonical_bytes(&value)).is_err());
    }

    #[test]
    fn rejects_whitespace_outside_the_canonical_document() {
        let source = include_bytes!("../../../c8s/allowlists/staging.json");
        let Ok(value) = serde_json::from_slice::<Value>(source) else {
            panic!("the public allowlist test fixture must contain JSON");
        };
        let mut leading = b" ".to_vec();
        leading.extend_from_slice(source);
        assert!(validate_allowlist(&value, &leading).is_err());

        let mut two_newlines = source.to_vec();
        two_newlines.extend_from_slice(b"\n");
        assert!(validate_allowlist(&value, &two_newlines).is_err());
    }
}
