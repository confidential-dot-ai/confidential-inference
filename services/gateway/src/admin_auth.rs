//! Authentication for admin requests that pass through c8s tls-lb.

use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

const MAX_CLOCK_SKEW_SECONDS: u64 = 60;
const MAX_ADMIN_BODY_BYTES: usize = 1_048_576;
const MAX_NONCES: usize = 4_096;

#[derive(Clone)]
pub struct AdminRequestVerifier {
    public_key: Arc<Vec<u8>>,
    nonces: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl AdminRequestVerifier {
    /// Load the exact admin client public certificate.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is absent, too large, malformed, or not P-256.
    pub fn from_certificate_file(path: &Path) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|_| "read the admin signer certificate")?;
        if bytes.is_empty() || bytes.len() > 256 * 1_024 {
            return Err("the admin signer certificate has an unsafe size".to_owned());
        }
        let (_, pem) = parse_x509_pem(&bytes).map_err(|_| "parse the admin signer PEM")?;
        let (_, certificate) = parse_x509_certificate(&pem.contents)
            .map_err(|_| "parse the admin signer certificate")?;
        let public_key = certificate.public_key().subject_public_key.data.to_vec();
        if public_key.len() != 65 || public_key.first() != Some(&4) {
            return Err("the admin signer certificate must use P-256".to_owned());
        }
        Ok(Self {
            public_key: Arc::new(public_key),
            nonces: Arc::new(Mutex::new(BTreeMap::new())),
        })
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
        nonces.retain(|_, seen| now.saturating_sub(*seen) <= MAX_CLOCK_SKEW_SECONDS);
        if nonces.contains_key(nonce) {
            return Err("replayed_signature");
        }
        if nonces.len() >= MAX_NONCES {
            return Err("nonce_store_full");
        }
        nonces.insert(nonce.to_owned(), now);
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
    if let Err(code) = verifier.verify(parts.method.as_str(), path, &parts.headers, &body, now) {
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
    use std::{error::Error, process::Command};

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
        let verifier = AdminRequestVerifier::from_certificate_file(&certificate)?;
        verifier.verify(method, path, &headers, body, 1_787_616_000)?;
        assert_eq!(
            verifier.verify(method, path, &headers, body, 1_787_616_000),
            Err("replayed_signature")
        );

        let other = AdminRequestVerifier::from_certificate_file(&certificate)?;
        assert_eq!(
            other.verify(method, path, &headers, b"changed", 1_787_616_000),
            Err("body_hash_mismatch")
        );
        Ok(())
    }
}
