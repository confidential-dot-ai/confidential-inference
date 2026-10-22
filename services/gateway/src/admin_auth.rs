//! Authentication for admin requests that pass through c8s tls-lb.
//!
//! An admin request carries either an admin API key
//! (`Authorization: Bearer <key>`) or the v1 request signature. The v1
//! signature stays until the admin cutover (issue #186).

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

const MAX_CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_ADMIN_BODY_BYTES: usize = 1_048_576;
const MAX_NONCES: usize = 4_096;

/// The largest admin signer certificate file that the gateway reads.
pub const MAX_CERTIFICATE_BYTES: usize = 256 * 1_024;
/// The largest admin API key hash file that the gateway reads.
pub const MAX_API_KEY_HASHES_BYTES: usize = 1_024;
const MAX_API_KEYS: usize = 2;

#[derive(Clone)]
pub struct AdminRequestVerifier {
    public_key: Arc<Vec<u8>>,
    nonces: Arc<Mutex<BTreeMap<String, u64>>>,
    api_key_hashes: Arc<Vec<[u8; 32]>>,
}

impl AdminRequestVerifier {
    /// Load the exact admin client public certificate from its PEM bytes.
    ///
    /// The caller reads the mounted file, so one bounded reader checks the
    /// shape of every mounted gateway input.
    ///
    /// # Errors
    ///
    /// Returns an error when the certificate is empty, too large, malformed, or not P-256.
    pub fn from_certificate_pem(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err("the admin signer certificate has an unsafe size".to_owned());
        }
        let (_, pem) = parse_x509_pem(bytes).map_err(|_| "parse the admin signer PEM")?;
        let (_, certificate) = parse_x509_certificate(&pem.contents)
            .map_err(|_| "parse the admin signer certificate")?;
        let public_key = certificate.public_key().subject_public_key.data.to_vec();
        if public_key.len() != 65 || public_key.first() != Some(&4) {
            return Err("the admin signer certificate must use P-256".to_owned());
        }
        Ok(Self {
            public_key: Arc::new(public_key),
            nonces: Arc::new(Mutex::new(BTreeMap::new())),
            api_key_hashes: Arc::new(Vec::new()),
        })
    }

    /// Accept the admin API keys whose SHA-256 the file lists.
    ///
    /// The file holds one lowercase hex SHA-256 per line, at most two, so a
    /// rotation can hold the old and the new key at once.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is empty or a line is not one SHA-256.
    pub fn with_api_key_hashes(mut self, bytes: &[u8]) -> Result<Self, String> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| "the admin API key hashes are not UTF-8")?;
        let mut hashes = Vec::new();
        for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let valid = line.len() == 64
                && line
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            let mut hash = [0_u8; 32];
            if !valid || hex::decode_to_slice(line, &mut hash).is_err() {
                return Err("an admin API key hash is not a lowercase hex SHA-256".to_owned());
            }
            hashes.push(hash);
        }
        if hashes.is_empty() || hashes.len() > MAX_API_KEYS {
            return Err(format!(
                "the admin API key file must list 1 to {MAX_API_KEYS} hashes"
            ));
        }
        self.api_key_hashes = Arc::new(hashes);
        Ok(self)
    }

    fn verify_api_key(&self, authorization: &str) -> Result<(), &'static str> {
        let key = authorization
            .strip_prefix("Bearer ")
            .ok_or("invalid_authorization")?;
        let presented: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        // Check every hash so the time does not show which one matched.
        let matched = self
            .api_key_hashes
            .iter()
            .fold(subtle::Choice::from(0), |found, hash| {
                found | hash.ct_eq(&presented)
            });
        if bool::from(matched) {
            Ok(())
        } else {
            Err("invalid_api_key")
        }
    }

    /// Return the P-256 public key bytes from the admin signer certificate.
    ///
    /// The key registry poller uses this key to verify a registry snapshot
    /// signature. The gateway gains no new trust root: it is the exact key
    /// this struct already uses to verify signed admin requests.
    #[must_use]
    pub fn public_key_bytes(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.public_key)
    }

    fn verify(
        &self,
        method: &str,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
        now: u64,
    ) -> Result<(), &'static str> {
        let version = one_header(headers, "x-admin-signature-version")?;
        let timestamp_text = one_header(headers, "x-admin-timestamp")?;
        let nonce = one_header(headers, "x-admin-nonce")?;
        let claimed_body_hash = one_header(headers, "x-admin-body-sha256")?;
        let signature_text = one_header(headers, "x-admin-signature")?;
        if version != "v1" {
            return Err("unsupported_signature_version");
        }
        let timestamp = timestamp_text
            .parse::<u64>()
            .map_err(|_| "invalid_timestamp")?;
        if now.abs_diff(timestamp) > MAX_CLOCK_SKEW_SECONDS {
            return Err("stale_signature");
        }
        if nonce.len() != 32 || !nonce.bytes().all(|value| value.is_ascii_hexdigit()) {
            return Err("invalid_nonce");
        }
        let body_hash = hex::encode(Sha256::digest(body));
        if claimed_body_hash != body_hash {
            return Err("body_hash_mismatch");
        }
        let canonical = canonical_request(method, path, timestamp_text, nonce, &body_hash);
        let signature = URL_SAFE_NO_PAD
            .decode(signature_text)
            .map_err(|_| "invalid_signature")?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, self.public_key.as_slice())
            .verify(canonical.as_bytes(), &signature)
            .map_err(|_| "invalid_signature")?;

        let mut nonces = self.nonces.lock().map_err(|_| "nonce_store_unavailable")?;
        nonces.retain(|_, expires_at| *expires_at >= now);
        if nonces.contains_key(nonce) {
            return Err("replayed_signature");
        }
        if nonces.len() >= MAX_NONCES {
            return Err("nonce_store_full");
        }
        // Keep the nonce for as long as the signed timestamp stays inside
        // the skew window, which outlives the receive time when the signer's
        // clock runs ahead.
        nonces.insert(
            nonce.to_owned(),
            timestamp.max(now).saturating_add(MAX_CLOCK_SKEW_SECONDS),
        );
        Ok(())
    }
}

pub async fn require_signed_admin_request(
    State(verifier): State<AdminRequestVerifier>,
    request: Request,
    next: Next,
) -> Response {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value.as_secs(),
        Err(_) => return rejection("clock_unavailable"),
    };
    let (parts, body) = request.into_parts();
    let Ok(body) = to_bytes(body, MAX_ADMIN_BODY_BYTES).await else {
        return rejection("invalid_body");
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |value| value.as_str());
    // A request that names an Authorization header is judged by it alone.
    let result = if parts.headers.contains_key(AUTHORIZATION) {
        one_header(&parts.headers, AUTHORIZATION.as_str())
            .and_then(|value| verifier.verify_api_key(value))
    } else {
        verifier.verify(parts.method.as_str(), path, &parts.headers, &body, now)
    };
    if let Err(code) = result {
        return rejection(code);
    }
    next.run(Request::from_parts(parts, Body::from(body))).await
}

#[must_use]
pub fn canonical_request(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body_hash: &str,
) -> String {
    format!("v1\n{timestamp}\n{nonce}\n{method}\n{path}\n{body_hash}\n")
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, &'static str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or("missing_signature")?;
    if values.next().is_some() {
        return Err("duplicate_signature_header");
    }
    value.to_str().map_err(|_| "invalid_signature_header")
}

fn rejection(code: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "code": code,
            "message": "The admin request is not authorized."
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fs, process::Command};

    use super::*;

    fn run(command: &mut Command) -> Result<(), Box<dyn Error>> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        Ok(())
    }

    #[test]
    fn valid_signature_is_accepted_once_and_binds_the_body() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key = directory.path().join("client.key");
        let certificate = directory.path().join("client.crt");
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
            .args(["-sha256", "-days", "1", "-subj", "/CN=admin-client", "-out"])
            .arg(&certificate))?;

        let method = "POST";
        let path = "/admin/v1/api-keys";
        let timestamp = "1787616000";
        let nonce = "0123456789abcdef0123456789abcdef";
        let body = br#"{"name":"test"}"#;
        let body_hash = hex::encode(Sha256::digest(body));
        let canonical = canonical_request(method, path, timestamp, nonce, &body_hash);
        let canonical_path = directory.path().join("canonical");
        let signature_path = directory.path().join("signature");
        fs::write(&canonical_path, canonical)?;
        run(Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&key)
            .args(["-out"])
            .arg(&signature_path)
            .arg(&canonical_path))?;
        let signature = URL_SAFE_NO_PAD.encode(fs::read(signature_path)?);
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-admin-signature-version", "v1"),
            ("x-admin-timestamp", timestamp),
            ("x-admin-nonce", nonce),
            ("x-admin-body-sha256", body_hash.as_str()),
            ("x-admin-signature", signature.as_str()),
        ] {
            headers.insert(name, value.parse()?);
        }
        let verifier = AdminRequestVerifier::from_certificate_pem(&fs::read(&certificate)?)?;
        verifier.verify(method, path, &headers, body, 1_787_616_000)?;
        assert_eq!(
            verifier.verify(method, path, &headers, body, 1_787_616_000),
            Err("replayed_signature")
        );

        let other = AdminRequestVerifier::from_certificate_pem(&fs::read(&certificate)?)?;
        assert_eq!(
            other.verify(method, path, &headers, b"changed", 1_787_616_000),
            Err("body_hash_mismatch")
        );
        Ok(())
    }

    #[test]
    fn a_signature_stays_rejected_until_its_timestamp_leaves_the_skew_window()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key = directory.path().join("client.key");
        let certificate = directory.path().join("client.crt");
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
            .args(["-sha256", "-days", "1", "-subj", "/CN=admin-client", "-out"])
            .arg(&certificate))?;

        let method = "POST";
        let path = "/admin/v1/api-keys";
        // Signed 60s ahead of the gateway clock at first receipt.
        let timestamp = "1787616060";
        let nonce = "fedcba9876543210fedcba9876543210";
        let body = br#"{"name":"test"}"#;
        let body_hash = hex::encode(Sha256::digest(body));
        let canonical = canonical_request(method, path, timestamp, nonce, &body_hash);
        let canonical_path = directory.path().join("canonical");
        let signature_path = directory.path().join("signature");
        fs::write(&canonical_path, canonical)?;
        run(Command::new("openssl")
            .args(["dgst", "-sha256", "-sign"])
            .arg(&key)
            .args(["-out"])
            .arg(&signature_path)
            .arg(&canonical_path))?;
        let signature = URL_SAFE_NO_PAD.encode(fs::read(signature_path)?);
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-admin-signature-version", "v1"),
            ("x-admin-timestamp", timestamp),
            ("x-admin-nonce", nonce),
            ("x-admin-body-sha256", body_hash.as_str()),
            ("x-admin-signature", signature.as_str()),
        ] {
            headers.insert(name, value.parse()?);
        }
        let verifier = AdminRequestVerifier::from_certificate_pem(&fs::read(&certificate)?)?;
        verifier.verify(method, path, &headers, body, 1_787_616_000)?;
        for now in [1_787_616_061, 1_787_616_120] {
            assert_eq!(
                verifier.verify(method, path, &headers, body, now),
                Err("replayed_signature")
            );
        }
        assert_eq!(
            verifier.verify(method, path, &headers, body, 1_787_616_121),
            Err("stale_signature")
        );
        Ok(())
    }

    fn key_only_verifier(hashes: &str) -> Result<AdminRequestVerifier, String> {
        AdminRequestVerifier {
            public_key: Arc::new(Vec::new()),
            nonces: Arc::new(Mutex::new(BTreeMap::new())),
            api_key_hashes: Arc::new(Vec::new()),
        }
        .with_api_key_hashes(hashes.as_bytes())
    }

    #[test]
    fn an_admin_api_key_is_accepted_only_when_its_hash_is_listed() -> Result<(), Box<dyn Error>> {
        let old = hex::encode(Sha256::digest(b"cia_old"));
        let new = hex::encode(Sha256::digest(b"cia_new"));
        let verifier = key_only_verifier(&format!("{old}\n{new}\n"))?;
        verifier.verify_api_key("Bearer cia_old")?;
        verifier.verify_api_key("Bearer cia_new")?;
        assert_eq!(
            verifier.verify_api_key("Bearer cia_other"),
            Err("invalid_api_key")
        );
        assert_eq!(
            verifier.verify_api_key("cia_new"),
            Err("invalid_authorization")
        );

        let without_keys = AdminRequestVerifier {
            public_key: Arc::new(Vec::new()),
            nonces: Arc::new(Mutex::new(BTreeMap::new())),
            api_key_hashes: Arc::new(Vec::new()),
        };
        assert_eq!(
            without_keys.verify_api_key("Bearer cia_new"),
            Err("invalid_api_key")
        );
        Ok(())
    }

    #[test]
    fn the_api_key_file_lists_one_or_two_lowercase_hashes() {
        let hash = hex::encode(Sha256::digest(b"cia_key"));
        assert!(key_only_verifier("").is_err());
        assert!(key_only_verifier(&hash.to_uppercase()).is_err());
        assert!(key_only_verifier(&hash[..63]).is_err());
        assert!(key_only_verifier(&format!("{hash}\n{hash}\n{hash}")).is_err());
    }
}
