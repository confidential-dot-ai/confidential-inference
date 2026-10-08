//! Test metadata sources with a local TLS server and a verifier stub.
//! These tests do not verify hardware evidence. Live checks must do that.

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    response::Response,
};
use confidential_gateway::attestation_metadata::{CdsMetadataSource, MetadataSource as _};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeSet,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use url::Url;

#[derive(Clone)]
struct Upstream {
    policy: Vec<u8>,
    keys: String,
    discovery: Value,
    paths: Arc<Mutex<BTreeSet<String>>>,
}

async fn read(State(state): State<Upstream>, request: Request) -> Response {
    let path = request.uri().path();
    state
        .paths
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(path.into());
    let bytes = match path {
        "/allowlist" => state.policy,
        "/operator-keys" => state.keys.into_bytes(),
        "/v1/discovery" => serde_json::to_vec(&state.discovery).unwrap_or_default(),
        _ => {
            return Response::builder()
                .status(404)
                .body(Body::empty())
                .unwrap_or_else(|error| panic!("{error}"));
        }
    };
    Response::new(Body::from(bytes))
}

#[tokio::test]
async fn reads_only_cds_and_discovery_and_hashes_exact_policy_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/contracts/fixtures/workload-attestation.v3.valid.json"
    ))?;
    let mut policy = serde_json::to_vec(&fixture["c8s"]["activeAllowlist"]["document"])?;
    policy.push(b'\n'); // The digest must include the received newline.
    let (keys, fingerprint) = operator_key()?;
    let paths = Arc::new(Mutex::new(BTreeSet::new()));
    let upstream = Upstream {
        policy: policy.clone(),
        keys: keys.clone(),
        discovery: fixture["c8s"]["discovery"].clone(),
        paths: paths.clone(),
    };
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let certificate_sha256 = format!("{:x}", Sha256::digest(certificate.cert.der()));
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate.cert.pem().into_bytes(),
        certificate.signing_key.serialize_pem().into_bytes(),
    )
    .await?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)
            .handle(handle)
            .serve(
                Router::new()
                    .fallback(read)
                    .with_state(upstream)
                    .into_make_service(),
            )
            .await
    });
    let directory = tempfile::tempdir()?;
    let policy_path = directory.path().join("policy.json");
    std::fs::write(&policy_path, br#"{"measurements":[{}]}"#)?;
    let verdict_path = directory.path().join("verdict.json");
    let verifier_path = write_verifier(directory.path(), &verdict_path)?;
    let verdict = json!({"verified": true, "measurement_pinned": true, "cert_sha256": certificate_sha256, "operator_keys": [fingerprint]});
    std::fs::write(&verdict_path, serde_json::to_vec(&verdict)?)?;
    let cds_url = Url::parse(&format!("https://localhost:{}", address.port()))?;
    let source = CdsMetadataSource {
        cds_url: cds_url.clone(),
        discovery_url: cds_url.join("/v1/discovery")?,
        allowlist_url: Url::parse("https://example.test/allowlist")?,
        release_id: "v1.0.0".into(),
        release_url: Url::parse(
            "https://github.com/confidential-dot-ai/confidential-inference/releases/tag/v1.0.0",
        )?,
        bundle_sha256: format!("sha256:{}", "0".repeat(64)),
        verifier: verifier_path,
        served_image_policy: policy_path.clone(),
        served_image_policy_sha256: format!(
            "sha256:{:x}",
            Sha256::digest(br#"{"measurements":[{}]}"#)
        ),
        image_policy: PathBuf::from(&policy_path),
        image_policy_sha256: format!("sha256:{:x}", Sha256::digest(br#"{"measurements":[{}]}"#)),
        timeout: Duration::from_secs(2),
        maximum_bytes: 1024 * 1024,
        discovery_client: reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_der(certificate.cert.der())?)
            .build()?,
    };
    let response = source.fetch().await.map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        std::fs::read(directory.path().join("checked-policy"))?,
        br#"{"measurements":[{}]}"#
    );
    let verifier_input = std::fs::read_to_string(directory.path().join("checked-policy-path"))?;
    assert_ne!(PathBuf::from(verifier_input.trim()), policy_path);
    assert_eq!(response["schemaVersion"], 3);
    assert_eq!(response["c8s"]["discovery"], fixture["c8s"]["discovery"]);
    assert_exact_policy(&response, &fixture, &policy);
    assert_eq!(response["c8s"]["operatorKeys"], json!([keys]));
    assert_eq!(
        *paths
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        BTreeSet::from([
            "/allowlist".into(),
            "/operator-keys".into(),
            "/v1/discovery".into()
        ])
    );
    reject_bad_verdicts(&source, &verdict_path, &verdict).await?;
    shutdown.shutdown();
    task.await??;
    Ok(())
}

async fn reject_bad_verdicts(
    source: &CdsMetadataSource,
    verdict_path: &std::path::Path,
    verdict: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    for (field, bad) in [
        ("verified", json!(false)),
        ("warnings", json!(["agent identity can pass as CDS"])),
        ("measurement_pinned", json!(false)),
        ("cert_sha256", json!("0".repeat(64))),
        ("operator_keys", json!(["0".repeat(64)])),
        (
            "operator_keys_note",
            json!("not fetched: connection failed"),
        ),
    ] {
        let mut changed = verdict.clone();
        changed[field] = bad;
        std::fs::write(verdict_path, serde_json::to_vec(&changed)?)?;
        assert!(source.fetch().await.is_err(), "must reject invalid {field}");
    }
    Ok(())
}

fn write_verifier(
    directory: &std::path::Path,
    verdict_path: &std::path::Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let verifier_path = directory.join("verifier");
    // The generated temporary path contains no shell metacharacters.
    std::fs::write(
        &verifier_path,
        format!(
            "#!/bin/sh\nprintf '%s' \"$8\" > '{}/checked-policy-path'\n/bin/cat \"$8\" > '{}/checked-policy'\nexec /bin/cat '{}'\n",
            directory.display(),
            directory.display(),
            verdict_path.display()
        ),
    )?;
    std::fs::set_permissions(&verifier_path, std::fs::Permissions::from_mode(0o700))?;
    Ok(verifier_path)
}

fn operator_key() -> Result<(String, String), Box<dyn std::error::Error>> {
    let key = rcgen::KeyPair::generate()?;
    let der = rcgen::PublicKeyData::subject_public_key_info(&key);
    let keys = key.public_key_pem();
    let fingerprint = format!("{:x}", Sha256::digest(&der));
    Ok((keys, fingerprint))
}

fn assert_exact_policy(response: &Value, fixture: &Value, policy: &[u8]) {
    assert_eq!(
        response["c8s"]["activeAllowlist"]["document"],
        fixture["c8s"]["activeAllowlist"]["document"]
    );
    assert_eq!(
        response["c8s"]["activeAllowlist"]["sha256"],
        format!("sha256:{:x}", Sha256::digest(policy))
    );
    assert_ne!(
        response["c8s"]["activeAllowlist"]["sha256"],
        format!("sha256:{:x}", Sha256::digest(&policy[..policy.len() - 1]))
    );
}
