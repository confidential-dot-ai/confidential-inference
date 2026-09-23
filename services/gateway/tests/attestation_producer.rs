use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Query, State},
    http::{Request, StatusCode},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use base64::Engine as _;
use confidential_gateway::{
    ApiKeyVerifier, AttestationProvider, AuditEvent, AuditSink, GatewayAvailability, GatewayConfig,
    attestation::{C8sAttestationConfig, C8sAttestationProvider},
    metrics::GatewayMetrics,
    router,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};
use tower::ServiceExt as _;

/// The pinned operator key set this test deployment declares. These are the
/// SPKI fingerprint and the c8s key-set commitment of one EC public key. The
/// same vector is reproduced in
/// `tests/attestation-v0/test_verify_public_attestation.py`, which is where
/// the canonical key-set formula now lives.
const TEST_OPERATOR_KEY_SHA256: &str =
    "sha256:45363125cde63f66880a4ba62fb4e0b48ae2f21bf1658df1fe1d6f14ec9ebfb7";
const TEST_OPERATOR_KEY_SET_SHA256: &str =
    "sha256:8e4a722def684a9495d9d024e84fdccbbae9cb7ad9f585e863f7e5df575d2355";

/// Byte length of one X-Wing encapsulation key: ML-KEM-768 plus X25519.
const XWING_ENCAPSULATION_KEY_BYTES: usize = 1_216;
/// Byte length of one X-Wing ciphertext.
const XWING_CIPHERTEXT_BYTES: usize = 1_120;
/// Byte length of one c8s session identifier.
const C8S_SESSION_ID_BYTES: usize = 16;

#[derive(Clone, Copy)]
enum FakeMode {
    Valid,
    NotReady,
    FailedReceipt,
    WrongNonce,
    MissingChain,
    WrongXwingEcho,
    LegacyProtocol,
    Cds,
    TeeWebPki,
    TeeWebPkiWrongFrontDoor,
    Static,
}

#[derive(Clone)]
struct FakeState {
    mode: FakeMode,
    nonces: Arc<Mutex<Vec<String>>>,
    /// Every X-Wing encapsulation key this fake c8s received.
    encapsulation_keys: Arc<Mutex<Vec<String>>>,
    /// Serve the c8s main-line (#551) allowlist shape, which carries no
    /// top-level "digests" map.
    main_line_allowlist: bool,
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn ready(State(state): State<FakeState>) -> StatusCode {
    if matches!(state.mode, FakeMode::NotReady) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}

/// The c8s `attest-pq` receipt at the pinned commit (c8s 466ce79).
///
/// The captured shape carries `xwing_ek`, `xwing_ct` and `session_id`, and
/// carries no `session_pubkey`, no `gpu_attested`, no `nvidia_gpu`, and no
/// operator key set.
/// The long evidence and certificate values are truncated here; only the
/// structure matters to these tests.
fn receipt_body(state: &FakeState, nonce: &str, encapsulation_key: &str) -> Value {
    let returned_nonce = if matches!(state.mode, FakeMode::WrongNonce) {
        encode(&[9_u8; 32])
    } else {
        nonce.to_owned()
    };
    let chain = if matches!(state.mode, FakeMode::MissingChain) {
        "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n"
    } else {
        "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAg==\n-----END CERTIFICATE-----\n"
    };
    let echoed = if matches!(state.mode, FakeMode::WrongXwingEcho) {
        encode(&vec![7_u8; XWING_ENCAPSULATION_KEY_BYTES])
    } else {
        encapsulation_key.to_owned()
    };
    json!({
        "version": "c8s/attest-pq/v1",
        "platform": "tdx",
        "generation": "",
        "nonce": returned_nonce,
        "evidence": {"cc_eventlog": "raw-c8s-event-log", "quote": "standard-c8s-evidence"},
        "cds_cert_pem": chain,
        "front_door_mode": "webpki",
        "xwing_ek": echoed,
        "xwing_ct": encode(&vec![6_u8; XWING_CIPHERTEXT_BYTES]),
        "session_id": encode(&[5_u8; C8S_SESSION_ID_BYTES]),
        "identity_proof": {
            "algorithm": "ecdsa-sha384",
            "leaf_sha256": encode(&[3_u8; 32]),
            "mesh_ca_sha256": encode(&[4_u8; 32]),
            "signature": encode(&[5_u8; 64])
        }
    })
}

/// The pinned c8s protocol: `attest-pq` is client-first and takes a POST body.
async fn receipt(State(state): State<FakeState>, body: Option<Json<Value>>) -> Response {
    if matches!(state.mode, FakeMode::FailedReceipt) {
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":"attestation_unavailable"})),
        )
            .into_response();
    }
    if matches!(state.mode, FakeMode::LegacyProtocol) {
        // c8s 079aeb48 registers attest-pq as GET only, so the POST this
        // gateway sends is rejected before any evidence is produced.
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(json!({
                "error": "method_not_allowed",
                "message": "attest-pq requires GET with a nonce query parameter"
            })),
        )
            .into_response();
    }
    let Some(Json(body)) = body else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "message": "attest-pq is client-first: POST a JSON body with nonce and xwing_ek"
            })),
        )
            .into_response();
    };
    let requested = body
        .get("nonce")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let encapsulation_key = body
        .get("xwing_ek")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    state
        .nonces
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(requested.clone());
    state
        .encapsulation_keys
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(encapsulation_key.clone());
    (
        StatusCode::OK,
        Json(receipt_body(&state, &requested, &encapsulation_key)),
    )
        .into_response()
}

/// `attest-lb` did not change: it stays a GET with a nonce query parameter,
/// and it carries `serving_leaf_sha256` instead of the X-Wing material.
async fn front_door_receipt(
    State(state): State<FakeState>,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let requested = query.get("nonce").cloned().unwrap_or_default();
    let mut body = receipt_body(
        &state,
        &requested,
        &encode(&[1_u8; XWING_ENCAPSULATION_KEY_BYTES]),
    );
    if matches!(state.mode, FakeMode::TeeWebPkiWrongFrontDoor) {
        return (StatusCode::OK, Json(body));
    }
    let object = body.as_object_mut().unwrap_or_else(|| unreachable!());
    object.insert("version".to_owned(), json!("c8s/attest-lb/v1"));
    object.remove("xwing_ek");
    object.remove("xwing_ct");
    object.remove("session_id");
    object.insert("serving_leaf_sha256".to_owned(), json!(encode(&[8_u8; 32])));
    (StatusCode::OK, Json(body))
}

async fn discovery(State(state): State<FakeState>) -> Json<Value> {
    Json(json!({
        "version": "v1",
        "generated_at": "2026-09-01T00:00:00Z",
        "public_tls": {"hostname": "api.example.test", "mode": if matches!(state.mode, FakeMode::Cds) { "cds" } else if matches!(state.mode, FakeMode::Static) { "acme" } else if matches!(state.mode, FakeMode::TeeWebPki | FakeMode::TeeWebPkiWrongFrontDoor) { "tee-webpki" } else { "webpki" }},
        "cds_tls": {
            "certificate_pem": "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n",
            "certificate_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "urls": ["https://cds.example.test:8443"]
        },
        "attestation": {"platform": "tdx", "evidence": {"quote": "raw-c8s-discovery-evidence"}}
    }))
}

fn exact_container() -> Value {
    let digest = format!("sha256:{}", "1".repeat(64));
    json!({
        "image": format!("ghcr.io/example/test@{digest}"),
        "digest": digest,
        "command": {"policy": "exact", "argv": ["/bin/test"]},
        "args": {"policy": "deny", "argv": []}
    })
}

fn allowlist_document() -> Value {
    let mut workloads = serde_json::Map::new();
    for name in [
        "gateway",
        "sglang-router",
        "inference-worker-0",
        "inference-worker-1",
        "metrics-collector",
        "kube-state-metrics",
        "extra-worker",
    ] {
        workloads.insert(
            name.to_owned(),
            json!({"identity": name, "initContainers": [], "containers": [exact_container()]}),
        );
    }
    json!({"schema": "c8s.allowlist/v1", "digests": {}, "workloads": workloads})
}

/// The c8s main-line (#551) document shape: the same workload entries and no
/// top-level "digests" map. The former floor digests arrive as workload
/// entries whose containers leave argv unconstrained.
fn main_line_allowlist_document() -> Value {
    let Value::Object(mut document) = allowlist_document() else {
        unreachable!()
    };
    document.remove("digests");
    let floor_digest = format!("sha256:{}", "3".repeat(64));
    document["workloads"][format!("cds-{}", &floor_digest[7..19])] = json!({
        "label": format!("ghcr.io/confidential-dot-ai/cds@{floor_digest}"),
        "initContainers": [],
        "containers": [{
            "digest": floor_digest,
            "image": format!("ghcr.io/confidential-dot-ai/cds@{floor_digest}"),
            "command": {"policy": "any"},
            "args": {"policy": "any"},
        }],
    });
    Value::Object(document)
}

async fn allowlist(State(state): State<FakeState>) -> Json<Value> {
    if state.main_line_allowlist {
        Json(main_line_allowlist_document())
    } else {
        Json(allowlist_document())
    }
}

struct FakeSidecar {
    url: String,
    nonces: Arc<Mutex<Vec<String>>>,
    encapsulation_keys: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

async fn fake_sidecar(mode: FakeMode) -> FakeSidecar {
    fake_sidecar_serving(mode, false).await
}

async fn fake_sidecar_serving(mode: FakeMode, main_line_allowlist: bool) -> FakeSidecar {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let nonces = Arc::new(Mutex::new(Vec::new()));
    let encapsulation_keys = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/readyz", get(ready))
        .route("/.well-known/c8s/attest-pq", post(receipt))
        .route("/.well-known/c8s/attest-lb", get(front_door_receipt))
        .route("/v1/discovery", get(discovery))
        .route("/allowlist", get(allowlist))
        .with_state(FakeState {
            mode,
            nonces: nonces.clone(),
            encapsulation_keys: encapsulation_keys.clone(),
            main_line_allowlist,
        });
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    FakeSidecar {
        url: format!("http://{address}"),
        nonces,
        encapsulation_keys,
        task,
    }
}

fn targets(base_url: &str, workloads: &[&str]) -> String {
    workloads
        .iter()
        .map(|target| {
            let workload = if target.starts_with("extra-worker-") {
                "extra-worker"
            } else {
                target
            };
            format!("{target}|{workload}|{workload}={base_url}")
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn provider(base_url: &str) -> C8sAttestationProvider {
    C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &targets(
            base_url,
            &[
                "gateway",
                "sglang-router",
                "inference-worker-0",
                "inference-worker-1",
                "metrics-collector",
                "kube-state-metrics",
            ],
        ),
        evidence_base_url: base_url,
        release_id: "test-release",
        release_bundle_sha256: &format!("sha256:{}", "2".repeat(64)),
        expected_operator_public_key_sha256: TEST_OPERATOR_KEY_SHA256,
        expected_operator_key_set_sha256: TEST_OPERATOR_KEY_SET_SHA256,
        policy_mode: "operator",
        expected_static_allowlist_sha256: "",
        timeout: Duration::from_secs(2),
        maximum_receipt_bytes: 1_048_576,
    })
    .unwrap_or_else(|error| panic!("provider: {error}"))
}

fn staging_provider(base_url: &str) -> C8sAttestationProvider {
    C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &targets(
            base_url,
            &[
                "gateway",
                "sglang-router",
                "extra-worker-0",
                "extra-worker-1",
            ],
        ),
        evidence_base_url: base_url,
        release_id: "test-release",
        release_bundle_sha256: &format!("sha256:{}", "2".repeat(64)),
        expected_operator_public_key_sha256: TEST_OPERATOR_KEY_SHA256,
        expected_operator_key_set_sha256: TEST_OPERATOR_KEY_SET_SHA256,
        policy_mode: "operator",
        expected_static_allowlist_sha256: "",
        timeout: Duration::from_secs(2),
        maximum_receipt_bytes: 1_048_576,
    })
    .unwrap_or_else(|error| panic!("provider: {error}"))
}

fn static_provider(base_url: &str, expected_digest: &str) -> C8sAttestationProvider {
    C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &targets(
            base_url,
            &[
                "gateway",
                "sglang-router",
                "inference-worker-0",
                "inference-worker-1",
                "metrics-collector",
                "kube-state-metrics",
            ],
        ),
        evidence_base_url: base_url,
        release_id: "test-release",
        release_bundle_sha256: &format!("sha256:{}", "2".repeat(64)),
        expected_operator_public_key_sha256: "",
        expected_operator_key_set_sha256: "",
        policy_mode: "static",
        expected_static_allowlist_sha256: expected_digest,
        timeout: Duration::from_secs(2),
        maximum_receipt_bytes: 1_048_576,
    })
    .unwrap_or_else(|error| panic!("provider: {error}"))
}

fn test_allowlist_digest() -> String {
    let bytes = serde_json::to_vec(&allowlist_document()).unwrap_or_else(|_| unreachable!());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn main_line_allowlist_digest() -> String {
    let bytes =
        serde_json::to_vec(&main_line_allowlist_document()).unwrap_or_else(|_| unreachable!());
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, _: &str) -> Option<String> {
        None
    }
}

struct Audit;

impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

fn gateway(provider: C8sAttestationProvider) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: "http://127.0.0.1:1".to_owned(),
            maximum_body_bytes: 1_024,
            upstream_timeout: Duration::from_secs(1),
            protection: confidential_gateway::protection::ProtectionConfig::default(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        GatewayAvailability::default(),
        Arc::new(provider),
        reqwest::Client::new(),
    )
}

async fn request(app: Router, nonce: &[u8; 32]) -> (StatusCode, Value) {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/attestation?nonce={encoded}"))
                .body(Body::empty())
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    let status = response.status();
    let body = to_bytes(response.into_body(), 8 * 1_024 * 1_024)
        .await
        .unwrap_or_default();
    (status, serde_json::from_slice(&body).unwrap_or_default())
}

#[tokio::test]
async fn one_nonce_collects_each_production_workload_receipt_once() {
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let nonce = [6_u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let (status, response) = request(gateway(provider(&sidecar.url)), &nonce).await;
    sidecar.task.abort();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["schemaVersion"], 2);
    assert_eq!(response["scope"], "launch-or-admission-only");
    assert_eq!(response["operationalStatus"], "not-verified");
    assert!(response.get("releaseBundleDigest").is_none());
    assert_eq!(response["release"]["id"], "test-release");
    assert_eq!(response["c8s"]["discovery"]["version"], "v1");
    assert!(response["c8s"]["policyTrust"].is_null());
    assert_eq!(
        response["c8s"]["operatorTrust"]["activeKeySetStatus"],
        "requires-attested-cds-read"
    );
    assert_eq!(
        response["c8s"]["operatorTrust"]["expectedKeySetSha256"],
        TEST_OPERATOR_KEY_SET_SHA256
    );
    assert_eq!(
        response["c8s"]["operatorTrust"]["cdsAttestedReadHint"],
        "/operator-keys"
    );
    assert_eq!(
        response["c8s"]["attestationProtocol"],
        "c8s/attest-pq/v1+xwing"
    );
    assert_eq!(response["c8s"]["attestationProtocolC8sCommit"], "466ce79");
    assert_eq!(response["tls"]["binding"]["status"], "not-proven");
    assert_eq!(response["gpuEvidence"]["status"], "not-exposed-by-c8s");
    assert_eq!(response["gpuEvidence"]["evidence"], json!([]));
    assert_eq!(response["receipts"].as_array().map_or(0, Vec::len), 6);
    let receipt_items = response["receipts"]
        .as_array()
        .unwrap_or_else(|| unreachable!());
    let targets = receipt_items
        .iter()
        .filter_map(|item| item["target"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        [
            "gateway",
            "inference-worker-0",
            "inference-worker-1",
            "kube-state-metrics",
            "metrics-collector",
            "sglang-router"
        ]
    );
    let workloads = receipt_items
        .iter()
        .filter_map(|item| item["workload"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        workloads,
        [
            "gateway",
            "inference-worker-0",
            "inference-worker-1",
            "kube-state-metrics",
            "metrics-collector",
            "sglang-router"
        ]
    );
    assert!(response["receipts"].as_array().is_some_and(|items| {
        items.iter().all(|item| {
            item["receipt"]["version"] == "c8s/attest-pq/v1"
                && item["receipt"]["nonce"] == encoded
                && item["receipt"]["session_pubkey"].is_null()
                && item["receipt"]["xwing_ct"].is_string()
                && item["receipt"]["session_id"].is_string()
                && item["admittedLaunch"]["containers"][0]["argv"][0] == "/bin/test"
        })
    }));
    assert_eq!(
        *sidecar
            .nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![encoded; 6]
    );
}

#[tokio::test]
async fn tee_webpki_discovery_mode_is_accepted() {
    let sidecar = fake_sidecar(FakeMode::TeeWebPki).await;
    let response = provider(&sidecar.url)
        .response(&[13_u8; 32])
        .await
        .unwrap_or_default();
    sidecar.task.abort();
    assert_eq!(
        response["c8s"]["discovery"]["public_tls"]["mode"],
        "tee-webpki"
    );
    assert_eq!(response["tls"]["binding"]["status"], "requires-attest-lb");
    assert_eq!(response["frontDoor"]["source"], "c8s-tls-lb");
    assert_eq!(
        response["frontDoor"]["receipt"]["version"],
        "c8s/attest-lb/v1"
    );
    assert!(response["frontDoor"]["receipt"]["session_pubkey"].is_null());
    assert!(response["receipts"].as_array().is_some_and(|items| {
        items
            .iter()
            .all(|item| item["receipt"]["version"] == "c8s/attest-pq/v1")
    }));
}

#[tokio::test]
async fn static_policy_accepts_no_operator_key_and_pins_the_allowlist() {
    let sidecar = fake_sidecar(FakeMode::Static).await;
    let digest = test_allowlist_digest();
    let response = static_provider(&sidecar.url, &digest)
        .response(&[18_u8; 32])
        .await
        .unwrap_or_default();
    sidecar.task.abort();

    assert_eq!(response["c8s"]["policyTrust"]["mode"], "static");
    assert_eq!(
        response["c8s"]["policyTrust"]["status"],
        "evidence-present-requires-independent-verification"
    );
    assert_eq!(
        response["c8s"]["policyTrust"]["activeAllowlistSha256"],
        digest
    );
    assert_eq!(response["tls"]["mode"], "acme");
    assert_eq!(
        response["frontDoor"]["receipt"]["version"],
        "c8s/attest-lb/v1"
    );
}

#[tokio::test]
async fn static_policy_rejects_a_different_allowlist_digest() {
    let sidecar = fake_sidecar(FakeMode::Static).await;
    let result = static_provider(&sidecar.url, &format!("sha256:{}", "0".repeat(64)))
        .response(&[19_u8; 32])
        .await;
    sidecar.task.abort();
    assert!(result.is_err());
}

#[tokio::test]
async fn main_line_allowlist_shape_is_accepted() {
    let sidecar = fake_sidecar_serving(FakeMode::Valid, true).await;
    let nonce = [21_u8; 32];
    let (status, response) = request(gateway(provider(&sidecar.url)), &nonce).await;
    sidecar.task.abort();

    assert_eq!(status, StatusCode::OK);
    let document = &response["c8s"]["activeAllowlist"]["document"];
    assert!(document.get("digests").is_none());
    assert!(document["workloads"].as_object().is_some_and(|workloads| {
        workloads
            .keys()
            .any(|name| name.starts_with("cds-") && name.len() == 16)
    }));
    // The reported digest commits to the exact main-line document bytes.
    assert_eq!(
        response["c8s"]["activeAllowlist"]["sha256"],
        main_line_allowlist_digest()
    );
    // Every receipt still resolves its admitted launch policy from the
    // per-workload entries.
    assert_eq!(
        response["c8s"]["operatorTrust"]["activeKeySetStatus"],
        "requires-attested-cds-read"
    );
    assert!(response["receipts"].as_array().is_some_and(|items| {
        !items.is_empty()
            && items
                .iter()
                .all(|item| item["admittedLaunch"]["containers"][0]["argv"][0] == "/bin/test")
    }));
}

#[tokio::test]
async fn static_policy_pins_the_main_line_allowlist() {
    let sidecar = fake_sidecar_serving(FakeMode::Static, true).await;
    let digest = main_line_allowlist_digest();
    let response = static_provider(&sidecar.url, &digest)
        .response(&[22_u8; 32])
        .await
        .unwrap_or_default();
    sidecar.task.abort();

    assert_eq!(response["c8s"]["policyTrust"]["mode"], "static");
    assert_eq!(
        response["c8s"]["policyTrust"]["activeAllowlistSha256"],
        digest
    );
}

#[tokio::test]
async fn static_policy_rejects_the_branch_digest_against_a_main_line_allowlist() {
    // Adding the branch's empty top-level "digests" map changes the canonical
    // bytes, so an expectation pinned to the branch shape fails closed
    // against a main-line CDS.
    let sidecar = fake_sidecar_serving(FakeMode::Static, true).await;
    let result = static_provider(&sidecar.url, &test_allowlist_digest())
        .response(&[23_u8; 32])
        .await;
    sidecar.task.abort();
    assert!(result.is_err());
}

#[tokio::test]
async fn cds_discovery_mode_requires_a_separate_front_door_receipt() {
    let sidecar = fake_sidecar(FakeMode::Cds).await;
    let response = provider(&sidecar.url)
        .response(&[14_u8; 32])
        .await
        .unwrap_or_default();
    sidecar.task.abort();
    assert_eq!(response["c8s"]["discovery"]["public_tls"]["mode"], "cds");
    assert_eq!(response["frontDoor"]["source"], "c8s-tls-lb");
    assert_eq!(
        response["frontDoor"]["receipt"]["version"],
        "c8s/attest-lb/v1"
    );
}

#[tokio::test]
async fn tee_webpki_front_door_failure_does_not_use_gateway_receipt() {
    let sidecar = fake_sidecar(FakeMode::TeeWebPki).await;
    let provider = provider(&sidecar.url);
    let response = provider.response(&[13_u8; 32]).await.unwrap_or_default();
    sidecar.task.abort();
    assert_eq!(
        response["frontDoor"]["receipt"]["version"],
        "c8s/attest-lb/v1"
    );
    assert_eq!(
        response["receipts"][0]["receipt"]["version"],
        "c8s/attest-pq/v1"
    );
}

#[tokio::test]
async fn tee_webpki_rejects_a_gateway_pq_receipt_at_the_front_door() {
    let sidecar = fake_sidecar(FakeMode::TeeWebPkiWrongFrontDoor).await;
    let (status, _) = request(gateway(provider(&sidecar.url)), &[15_u8; 32]).await;
    sidecar.task.abort();
    assert!(matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE
    ));
}

#[tokio::test]
async fn staging_collects_the_exact_extra_worker_receipt_set() {
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let nonce = [10_u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let (status, response) = request(gateway(staging_provider(&sidecar.url)), &nonce).await;
    sidecar.task.abort();

    assert_eq!(status, StatusCode::OK);
    let receipt_items = response["receipts"]
        .as_array()
        .unwrap_or_else(|| unreachable!());
    let targets = receipt_items
        .iter()
        .filter_map(|item| item["target"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        targets,
        [
            "extra-worker-0",
            "extra-worker-1",
            "gateway",
            "sglang-router"
        ]
    );
    let workloads = receipt_items
        .iter()
        .filter_map(|item| item["workload"].as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        workloads,
        ["extra-worker", "extra-worker", "gateway", "sglang-router"]
    );
    assert_eq!(
        *sidecar
            .nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![encoded; 4]
    );
    assert_eq!(response["scope"], "launch-or-admission-only");
    assert_eq!(response["operationalStatus"], "not-verified");
}

#[tokio::test]
async fn configured_identity_cannot_replace_the_allowlist_identity() {
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let targets = format!("gateway|gateway|attacker={}", sidecar.url);
    let provider = C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &targets,
        evidence_base_url: &sidecar.url,
        release_id: "test-release",
        release_bundle_sha256: &format!("sha256:{}", "2".repeat(64)),
        expected_operator_public_key_sha256: TEST_OPERATOR_KEY_SHA256,
        expected_operator_key_set_sha256: TEST_OPERATOR_KEY_SET_SHA256,
        policy_mode: "operator",
        expected_static_allowlist_sha256: "",
        timeout: Duration::from_secs(2),
        maximum_receipt_bytes: 1_048_576,
    })
    .unwrap_or_else(|error| panic!("provider: {error}"));
    let response = provider.response(&[17_u8; 32]).await;
    sidecar.task.abort();
    assert!(response.is_err());
}

#[tokio::test]
async fn any_failed_or_invalid_receipt_fails_closed() {
    for mode in [
        FakeMode::NotReady,
        FakeMode::FailedReceipt,
        FakeMode::WrongNonce,
        FakeMode::MissingChain,
    ] {
        let sidecar = fake_sidecar(mode).await;
        let (status, _) = request(gateway(provider(&sidecar.url)), &[7_u8; 32]).await;
        sidecar.task.abort();
        assert!(matches!(
            status,
            StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE
        ));
    }
}

#[tokio::test]
async fn the_post_body_carries_the_nonce_and_one_fresh_encapsulation_key() {
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let nonce = [24_u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let (status, response) = request(gateway(provider(&sidecar.url)), &nonce).await;
    let keys = sidecar
        .encapsulation_keys
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    sidecar.task.abort();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys.len(), 6);
    for key in &keys {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key)
            .unwrap_or_default();
        assert_eq!(decoded.len(), XWING_ENCAPSULATION_KEY_BYTES);
    }
    // Each request generates its own ephemeral key.
    let mut unique = keys.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), keys.len());
    // The receipt echoes the exact key the gateway sent.
    let receipts = response["receipts"]
        .as_array()
        .unwrap_or_else(|| unreachable!());
    assert!(
        receipts
            .iter()
            .all(|item| keys.iter().any(|key| item["receipt"]["xwing_ek"] == *key))
    );
    assert_eq!(
        *sidecar
            .nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        vec![encoded; 6]
    );
}

#[tokio::test]
async fn a_different_echoed_encapsulation_key_fails_closed() {
    let sidecar = fake_sidecar(FakeMode::WrongXwingEcho).await;
    let (status, body) = request(gateway(provider(&sidecar.url)), &[25_u8; 32]).await;
    sidecar.task.abort();
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"]["code"], "attestation_invalid");
}

#[tokio::test]
async fn an_old_protocol_node_reports_a_protocol_mismatch() {
    let sidecar = fake_sidecar(FakeMode::LegacyProtocol).await;
    let (status, body) = request(gateway(provider(&sidecar.url)), &[26_u8; 32]).await;
    sidecar.task.abort();
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"]["code"], "attestation_protocol_mismatch");
    let detail = body["error"]["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("405"), "detail: {detail}");
    assert!(detail.contains("method_not_allowed"), "detail: {detail}");
    assert!(
        detail.contains("attest-pq requires GET"),
        "detail: {detail}"
    );
    assert!(
        detail.contains("c8s/attest-pq/v1+xwing"),
        "detail: {detail}"
    );
}

#[tokio::test]
async fn the_operator_key_set_is_published_as_a_pin_and_a_read_hint() {
    // CDS serves GET /operator-keys over RA-TLS behind a self-signed
    // certificate. Its trust comes from a TEE evidence extension and a pinned
    // launch measurement, so no CA-trusting TLS client can verify it and the
    // gateway must not try. The gateway publishes the pinned expectation and
    // the route name, and the verifier performs the attested read itself.
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let response = provider(&sidecar.url)
        .response(&[27_u8; 32])
        .await
        .unwrap_or_default();
    sidecar.task.abort();

    let trust = &response["c8s"]["operatorTrust"];
    assert_eq!(trust["expectedKeySetSha256"], TEST_OPERATOR_KEY_SET_SHA256);
    assert_eq!(
        trust["expectedPublicKeySpkiSha256"],
        TEST_OPERATOR_KEY_SHA256
    );
    assert_eq!(trust["activeKeySetStatus"], "requires-attested-cds-read");
    assert_eq!(trust["cdsAttestedReadHint"], "/operator-keys");
    assert!(
        trust["reason"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    // The gateway never reports a live key set. A claimed active value would
    // read as proof the gateway cannot obtain.
    assert!(trust.get("activeKeySetSha256").is_none());
    assert!(trust.get("activeKeySetPem").is_none());
    assert!(trust.get("activeKeySetC8sSha256").is_none());
    // The weaker claim must never be reported as a hardware-bound match.
    assert_ne!(
        trust["activeKeySetStatus"],
        "evidence-present-and-release-matched"
    );
}

#[tokio::test]
async fn the_gateway_never_requests_the_cds_operator_key_route() {
    // A live read is the defect this release removes. The fake sidecar
    // registers no /operator-keys route, so any request would 404 and the
    // response would fail closed. A success proves no request is made.
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let (status, body) = request(gateway(provider(&sidecar.url)), &[14_u8; 32]).await;
    sidecar.task.abort();

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["c8s"]["operatorTrust"]["activeKeySetStatus"],
        "requires-attested-cds-read"
    );
}

#[tokio::test]
async fn the_folded_allowlist_needs_no_digests_key() {
    let sidecar = fake_sidecar_serving(FakeMode::Valid, true).await;
    let response = provider(&sidecar.url)
        .response(&[28_u8; 32])
        .await
        .unwrap_or_default();
    sidecar.task.abort();

    let allowlist = &response["c8s"]["activeAllowlist"];
    assert!(allowlist["document"].get("digests").is_none());
    assert_eq!(allowlist["document"]["schema"], "c8s.allowlist/v1");
    assert_eq!(allowlist["sha256"], main_line_allowlist_digest());
}

#[tokio::test]
async fn the_published_key_set_pin_is_the_configured_pin_verbatim() {
    // The gateway makes no live claim about the key set, so it can make no
    // comparison either. It must publish the configured pin unchanged, so
    // the verifier compares that value against both the release bundle and
    // its own attested CDS read.
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let targets = targets(
        &sidecar.url,
        &[
            "gateway",
            "sglang-router",
            "inference-worker-0",
            "inference-worker-1",
            "metrics-collector",
            "kube-state-metrics",
        ],
    );
    let provider = C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &targets,
        evidence_base_url: &sidecar.url,
        release_id: "test-release",
        release_bundle_sha256: &format!("sha256:{}", "2".repeat(64)),
        expected_operator_public_key_sha256: TEST_OPERATOR_KEY_SHA256,
        expected_operator_key_set_sha256: &format!("sha256:{}", "0".repeat(64)),
        policy_mode: "operator",
        expected_static_allowlist_sha256: "",
        timeout: Duration::from_secs(2),
        maximum_receipt_bytes: 1_048_576,
    })
    .unwrap_or_else(|error| panic!("provider: {error}"));
    let response = provider.response(&[12_u8; 32]).await;
    sidecar.task.abort();

    let response = response.unwrap_or_else(|error| panic!("response: {error:?}"));
    let trust = &response["c8s"]["operatorTrust"];
    assert_eq!(
        trust["expectedKeySetSha256"],
        format!("sha256:{}", "0".repeat(64))
    );
    assert_eq!(trust["activeKeySetStatus"], "requires-attested-cds-read");
}

#[tokio::test]
async fn each_request_uses_its_client_nonce() {
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let provider = provider(&sidecar.url);
    let first = provider.response(&[1_u8; 32]).await.unwrap_or_default();
    let second = provider.response(&[2_u8; 32]).await.unwrap_or_default();
    sidecar.task.abort();
    assert_ne!(first["nonce"], second["nonce"]);
    assert_ne!(
        first["receipts"][0]["receipt"]["nonce"],
        second["receipts"][0]["receipt"]["nonce"]
    );
}

#[test]
fn target_configuration_rejects_malformed_or_unsafe_entries() {
    for invalid in [
        "gateway=http://127.0.0.1:8800",
        "gateway|gateway=http://127.0.0.1:8800,gateway|gateway=http://127.0.0.1:8801",
        "gateway|gateway=https://public.example:443",
        "-gateway|gateway=http://127.0.0.1:8800",
    ] {
        assert!(
            C8sAttestationProvider::from_config(C8sAttestationConfig {
                targets: invalid,
                evidence_base_url: "https://api.example.test",
                release_id: "test-release",
                release_bundle_sha256: &format!("sha256:{}", "2".repeat(64)),
                expected_operator_public_key_sha256: TEST_OPERATOR_KEY_SHA256,
                expected_operator_key_set_sha256: TEST_OPERATOR_KEY_SET_SHA256,
                policy_mode: "operator",
                expected_static_allowlist_sha256: "",
                timeout: Duration::from_secs(2),
                maximum_receipt_bytes: 1_048_576,
            })
            .is_err()
        );
    }
}

#[tokio::test]
async fn response_does_not_claim_workload_liveness() {
    let sidecar = fake_sidecar(FakeMode::Valid).await;
    let (_, response) = request(gateway(provider(&sidecar.url)), &[8_u8; 32]).await;
    sidecar.task.abort();
    let text = serde_json::to_string(&response)
        .unwrap_or_default()
        .to_lowercase();
    assert!(!text.contains("\"running\""));
    assert!(!text.contains("\"liveness\""));
    assert!(!text.contains("\"live\""));
}

/// Read the `detail` string out of one gateway error body.
fn error_detail(body: &Value) -> String {
    body.pointer("/error/detail")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

// The gateway runs where kubelet logs and exec are disabled, so the response
// body is the only channel that can name the step that failed. Each test below
// drives one failing step and asserts the public error names it.

#[tokio::test]
async fn a_not_ready_sidecar_names_the_readyz_step_and_its_status() {
    let sidecar = fake_sidecar(FakeMode::NotReady).await;
    let (status, body) = request(gateway(provider(&sidecar.url)), &[21_u8; 32]).await;
    sidecar.task.abort();

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "attestation_unavailable");
    let detail = error_detail(&body);
    assert!(detail.contains("readyz"), "detail: {detail}");
    assert!(detail.contains("503"), "detail: {detail}");
    assert!(
        detail.contains("gateway attestation.rs:"),
        "detail: {detail}"
    );
}

#[tokio::test]
async fn a_failing_attest_pq_endpoint_names_the_attest_pq_step() {
    let sidecar = fake_sidecar(FakeMode::FailedReceipt).await;
    let (status, body) = request(gateway(provider(&sidecar.url)), &[22_u8; 32]).await;
    sidecar.task.abort();

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let detail = error_detail(&body);
    assert!(detail.contains("attest-pq"), "detail: {detail}");
    assert!(detail.contains("502"), "detail: {detail}");
    assert!(
        detail.contains("attestation_unavailable"),
        "the c8s error code is copied: {detail}"
    );
}

#[tokio::test]
async fn the_error_detail_never_carries_the_nonce_or_evidence_bytes() {
    let nonce = [25_u8; 32];
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let sidecar = fake_sidecar(FakeMode::FailedReceipt).await;
    let (_, body) = request(gateway(provider(&sidecar.url)), &nonce).await;
    sidecar.task.abort();

    let detail = error_detail(&body);
    assert!(!detail.is_empty());
    assert!(!detail.contains(&encoded), "detail carries the nonce");
    assert!(
        !detail.contains("BEGIN CERTIFICATE"),
        "detail carries certificate bytes"
    );
    assert!(detail.len() <= 220, "detail is unbounded: {}", detail.len());
    assert!(
        detail
            .chars()
            .all(|value| value.is_ascii_graphic() || value == ' '),
        "detail is not printable ASCII: {detail}"
    );
}
