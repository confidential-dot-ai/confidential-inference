//! Kubernetes process wiring for the confidential inference gateway.

use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use axum::middleware;
use clap::Parser;
use confidential_gateway::{
    GatewayConfig, TracingAuditSink,
    admin_auth::{AdminRequestVerifier, require_signed_admin_request},
    api_keys::{GatewayState, admin_router},
    attestation::{
        C8S_ATTESTATION_PROTOCOL, C8S_ATTESTATION_PROTOCOL_COMMIT, C8sAttestationConfig,
        C8sAttestationProvider,
    },
    metrics::{GatewayMetrics, metrics_router},
    protection::ProtectionConfig,
    router,
};
use hyper_util::rt::TokioTimer;

const MINIMAX_M3_MODEL_ID: &str = "MiniMaxAI/MiniMax-M3-MXFP8";
// The gateway must never dial the router Service directly. The c8s
// workload-proxy client owns this loopback port and provides the authenticated
// hop to the named router workload.
const INFERENCE_UPSTREAM_URL: &str = "http://127.0.0.1:30001";

#[derive(Parser, Debug)]
#[command(name = "confidential-gateway")]
struct Args {
    #[arg(long, env = "GATEWAY_LISTEN", default_value = "0.0.0.0:9443")]
    listen: SocketAddr,
    #[arg(long, env = "GATEWAY_METRICS_LISTEN", default_value = "0.0.0.0:9090")]
    metrics_listen: SocketAddr,
    #[arg(
        long,
        env = "GATEWAY_INFERENCE_URL",
        default_value = "http://127.0.0.1:30001"
    )]
    inference_url: String,
    // Named-workload-proxy-off deployments (main-line c8s ships no
    // workload-proxy binary) point the gateway straight at the in-cluster
    // router service instead of the loopback proxy hop. Fail-closed default:
    // only the exact loopback proxy URL is accepted without this flag.
    #[arg(long, env = "GATEWAY_ALLOW_DIRECT_INFERENCE_URL")]
    allow_direct_inference_url: bool,
    #[arg(long, env = "GATEWAY_MODEL")]
    model: String,
    #[arg(long, env = "GATEWAY_C8S_RECEIPT_TARGETS")]
    c8s_receipt_targets: String,
    #[arg(long, env = "GATEWAY_C8S_EVIDENCE_BASE_URL")]
    c8s_evidence_base_url: String,
    #[arg(long, env = "GATEWAY_RELEASE_ID")]
    release_id: String,
    #[arg(long, env = "GATEWAY_RELEASE_BUNDLE_SHA256")]
    release_bundle_sha256: String,
    #[arg(long, env = "GATEWAY_EXPECTED_OPERATOR_PUBLIC_KEY_SHA256")]
    expected_operator_public_key_sha256: String,
    #[arg(long, env = "GATEWAY_EXPECTED_OPERATOR_KEY_SET_SHA256")]
    expected_operator_key_set_sha256: String,
    #[arg(long, env = "GATEWAY_C8S_POLICY_MODE", default_value = "operator")]
    c8s_policy_mode: String,
    // The gateway and c8s run in lockstep on one attestation protocol. c8s
    // serves the same receipt `version` string in both protocols, so the
    // gateway cannot detect the protocol from a receipt and must not probe.
    // This flag exists to make the pin explicit in the deployment, not to
    // select a second protocol: only the pinned value is accepted.
    #[arg(
        long,
        env = "GATEWAY_C8S_ATTESTATION_PROTOCOL",
        default_value = "v1-xwing"
    )]
    c8s_attestation_protocol: String,
    #[arg(
        long,
        env = "GATEWAY_EXPECTED_STATIC_ALLOWLIST_SHA256",
        default_value = ""
    )]
    expected_static_allowlist_sha256: String,
    #[arg(
        long,
        env = "GATEWAY_ATTESTATION_TIMEOUT_SECONDS",
        default_value_t = 30
    )]
    attestation_timeout_seconds: u64,
    #[arg(
        long,
        env = "GATEWAY_ATTESTATION_MAXIMUM_EVIDENCE_BYTES",
        default_value_t = 1_048_576
    )]
    attestation_maximum_evidence_bytes: usize,
    #[arg(long, env = "DEPLOYMENT_ENVIRONMENT")]
    environment: String,
    #[arg(
        long,
        env = "GATEWAY_STATE_DATABASE",
        default_value = "/var/lib/confidential-gateway/gateway.sqlite3"
    )]
    state_database: PathBuf,
    #[arg(
        long,
        env = "GATEWAY_STATE_ABSENCE_POLICY",
        default_value = "fail-closed"
    )]
    state_absence_policy: String,
    #[arg(long, env = "GATEWAY_STATE_ENABLED", default_value_t = false)]
    state_enabled: bool,
    // The serial the state-volume marker must name. Compiled as a constant
    // for every deployment to date; confai-attached disks get their serials
    // from the volume name (c8s-vol-<name>), so those clusters set this.
    #[arg(
        long,
        env = "GATEWAY_STATE_DISK_SERIAL",
        default_value = "confai-gateway-state"
    )]
    state_disk_serial: String,
    #[arg(
        long,
        env = "GATEWAY_API_KEY_PEPPER_FILE",
        default_value = "/run/c8s/secrets/GATEWAY_API_KEY_PEPPER"
    )]
    api_key_pepper_file: PathBuf,
    #[arg(
        long,
        env = "GATEWAY_STATE_STARTUP_TIMEOUT_SECONDS",
        default_value_t = 60
    )]
    state_startup_timeout_seconds: u64,
    #[arg(
        long,
        env = "GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE",
        default_value = "/run/confidential-inference/admin-auth/client.crt"
    )]
    admin_signer_certificate_file: PathBuf,
    #[arg(long, env = "GATEWAY_MAXIMUM_BODY_BYTES", default_value_t = 2_097_152)]
    maximum_body_bytes: usize,
    #[arg(long, env = "GATEWAY_UPSTREAM_TIMEOUT_SECONDS", default_value_t = 900)]
    upstream_timeout_seconds: u64,
    #[arg(long, env = "GATEWAY_MAXIMUM_HEADERS", default_value_t = 64)]
    maximum_headers: usize,
    #[arg(long, env = "GATEWAY_MAXIMUM_HEADER_BYTES", default_value_t = 16_384)]
    maximum_header_bytes: usize,
    #[arg(long, env = "GATEWAY_MAXIMUM_URI_BYTES", default_value_t = 2_048)]
    maximum_uri_bytes: usize,
    #[arg(long, env = "GATEWAY_HEADER_TIMEOUT_SECONDS", default_value_t = 5)]
    header_timeout_seconds: u64,
    #[arg(long, env = "GATEWAY_BODY_TIMEOUT_SECONDS", default_value_t = 10)]
    body_timeout_seconds: u64,
    #[arg(
        long,
        env = "GATEWAY_STREAM_IDLE_TIMEOUT_SECONDS",
        default_value_t = 60
    )]
    stream_idle_timeout_seconds: u64,
    #[arg(
        long,
        env = "GATEWAY_GLOBAL_REQUEST_CONCURRENCY",
        default_value_t = 256
    )]
    global_request_concurrency: usize,
    #[arg(long, env = "GATEWAY_PER_ADDRESS_CONCURRENCY", default_value_t = 16)]
    per_address_concurrency: usize,
    #[arg(long, env = "GATEWAY_INFERENCE_CONCURRENCY", default_value_t = 64)]
    inference_concurrency: usize,
    #[arg(long, env = "GATEWAY_INFERENCE_QUEUE", default_value_t = 64)]
    inference_queue: usize,
    #[arg(long, env = "GATEWAY_QUEUE_TIMEOUT_SECONDS", default_value_t = 2)]
    queue_timeout_seconds: u64,
    #[arg(long, env = "GATEWAY_PER_KEY_CONCURRENCY", default_value_t = 4)]
    per_key_concurrency: usize,
    #[arg(long, env = "GATEWAY_ATTESTATION_CONCURRENCY", default_value_t = 4)]
    attestation_concurrency: usize,
    #[arg(
        long,
        env = "GATEWAY_REQUESTS_PER_ADDRESS_PER_SECOND",
        default_value_t = 30
    )]
    requests_per_address_per_second: u32,
    #[arg(long, env = "GATEWAY_SHUTDOWN_GRACE_SECONDS", default_value_t = 900)]
    shutdown_grace_seconds: u64,
    #[arg(long, env = "GATEWAY_ENDPOINT_DRAIN_SECONDS", default_value_t = 35)]
    endpoint_drain_seconds: u64,
    #[arg(long, env = "GATEWAY_TRUSTED_PROXY_CIDRS", value_delimiter = ',')]
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();
    validate_args(&args)?;

    let gateway_state = if args.state_enabled {
        let state_result = (|| -> Result<GatewayState> {
            let pepper = wait_for_bounded_file(
                &args.api_key_pepper_file,
                4_096,
                Duration::from_secs(args.state_startup_timeout_seconds),
            )?;
            GatewayState::open_persistent(
                &args.state_database,
                pepper,
                &args.environment,
                &args.state_disk_serial,
            )
            .map_err(anyhow::Error::from)
        })();
        match state_result {
            Ok(state) => state,
            Err(error) => {
                tracing::error!(error = %error, "the gateway entered outage-only mode");
                GatewayState::outage_only().context("create the outage-only gateway state")?
            }
        }
    } else {
        tracing::warn!("the gateway state feature is disabled; the gateway uses outage-only mode");
        GatewayState::outage_only().context("create the outage-only gateway state")?
    };
    let availability = gateway_state.availability_handle();
    let metrics = Arc::new(GatewayMetrics::new(args.environment.clone()));
    let timeout = Duration::from_secs(args.upstream_timeout_seconds);
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build the internal inference client")?;
    let attestation = C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &args.c8s_receipt_targets,
        evidence_base_url: &args.c8s_evidence_base_url,
        release_id: &args.release_id,
        release_bundle_sha256: &args.release_bundle_sha256,
        expected_operator_public_key_sha256: &args.expected_operator_public_key_sha256,
        expected_operator_key_set_sha256: &args.expected_operator_key_set_sha256,
        policy_mode: &args.c8s_policy_mode,
        expected_static_allowlist_sha256: &args.expected_static_allowlist_sha256,
        timeout: Duration::from_secs(args.attestation_timeout_seconds),
        maximum_receipt_bytes: args.attestation_maximum_evidence_bytes,
    })
    .map_err(anyhow::Error::msg)
    .context("load the fail-closed attestation producer")?;
    let protection = protection_config(&args);
    let inference_model_id = args.model;
    let mut catalog_model_ids = vec![inference_model_id.clone()];
    if inference_model_id != MINIMAX_M3_MODEL_ID {
        catalog_model_ids.push(MINIMAX_M3_MODEL_ID.to_owned());
    }
    let public = router(
        GatewayConfig {
            catalog_model_ids,
            inference_model_ids: vec![inference_model_id],
            upstream_base_url: args.inference_url.trim_end_matches('/').to_owned(),
            maximum_body_bytes: args.maximum_body_bytes,
            upstream_timeout: timeout,
            protection,
        },
        Arc::new(gateway_state.clone()),
        Arc::new(TracingAuditSink),
        metrics.clone(),
        availability,
        Arc::new(attestation),
        http,
    );
    let admin_verifier =
        AdminRequestVerifier::from_certificate_file(&args.admin_signer_certificate_file)
            .map_err(anyhow::Error::msg)
            .context("load the admin request signer certificate")?;
    let admin = admin_router(gateway_state).layer(middleware::from_fn_with_state(
        admin_verifier,
        require_signed_admin_request,
    ));
    let app = public.merge(admin);

    let metrics_listener = tokio::net::TcpListener::bind(args.metrics_listen)
        .await
        .context("bind the private metrics listener")?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(metrics_listener, metrics_router(metrics)).await {
            tracing::error!(%error, "the metrics listener stopped");
        }
    });

    tracing::info!(listen = %args.listen, environment = %args.environment, "the gateway is ready");
    let shutdown_handle = axum_server::Handle::new();
    let signal_handle = shutdown_handle.clone();
    let shutdown_grace = Duration::from_secs(args.shutdown_grace_seconds);
    let endpoint_drain = Duration::from_secs(args.endpoint_drain_seconds);
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!(
            drain_seconds = endpoint_drain.as_secs(),
            "the gateway started endpoint drain"
        );
        tokio::time::sleep(endpoint_drain).await;
        tracing::info!(
            grace_seconds = shutdown_grace.as_secs(),
            "the gateway started graceful shutdown"
        );
        signal_handle.graceful_shutdown(Some(shutdown_grace));
    });

    let mut public_server = axum_server::bind(args.listen).handle(shutdown_handle);
    public_server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(args.header_timeout_seconds))
        .max_headers(args.maximum_headers)
        .max_buf_size(args.maximum_header_bytes.max(8_192));
    let h2_streams =
        u32::try_from(args.inference_concurrency).context("convert the HTTP/2 stream limit")?;
    let h2_header_bytes =
        u32::try_from(args.maximum_header_bytes).context("convert the HTTP/2 header limit")?;
    public_server
        .http_builder()
        .http2()
        .max_concurrent_streams(h2_streams)
        .max_header_list_size(h2_header_bytes);
    public_server
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("serve the public gateway")
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let terminate = signal(SignalKind::terminate());
        let interrupt = signal(SignalKind::interrupt());
        match (terminate, interrupt) {
            (Ok(mut terminate), Ok(mut interrupt)) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = interrupt.recv() => {}
                }
            }
            _ => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn protection_config(args: &Args) -> ProtectionConfig {
    ProtectionConfig {
        maximum_headers: args.maximum_headers,
        maximum_header_bytes: args.maximum_header_bytes,
        maximum_uri_bytes: args.maximum_uri_bytes,
        body_timeout: Duration::from_secs(args.body_timeout_seconds),
        stream_idle_timeout: Duration::from_secs(args.stream_idle_timeout_seconds),
        global_request_concurrency: args.global_request_concurrency,
        per_address_concurrency: args.per_address_concurrency,
        inference_concurrency: args.inference_concurrency,
        inference_queue: args.inference_queue,
        queue_timeout: Duration::from_secs(args.queue_timeout_seconds),
        per_key_concurrency: args.per_key_concurrency,
        attestation_concurrency: args.attestation_concurrency,
        requests_per_address_per_second: args.requests_per_address_per_second,
        trusted_proxy_cidrs: args.trusted_proxy_cidrs.clone(),
    }
}

/// The only value `GATEWAY_C8S_ATTESTATION_PROTOCOL` accepts.
const PINNED_C8S_ATTESTATION_PROTOCOL: &str = "v1-xwing";

fn validate_args(args: &Args) -> Result<()> {
    if args.environment.is_empty()
        || args.environment.len() > 63
        || !args
            .environment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || args.environment.starts_with('-')
        || args.environment.ends_with('-')
    {
        bail!("DEPLOYMENT_ENVIRONMENT must be a DNS label");
    }
    if args.listen.port() != 9443 || args.metrics_listen.port() != 9090 {
        bail!("the gateway listeners do not match the Kubernetes port contract");
    }
    if !args.allow_direct_inference_url && args.inference_url != INFERENCE_UPSTREAM_URL {
        bail!(
            "GATEWAY_INFERENCE_URL must be the exact loopback proxy URL {INFERENCE_UPSTREAM_URL}              (or set GATEWAY_ALLOW_DIRECT_INFERENCE_URL for a proxy-less deployment)"
        );
    }
    if args.allow_direct_inference_url
        && !args.inference_url.starts_with("http://")
        && !args.inference_url.starts_with("https://")
    {
        bail!("GATEWAY_INFERENCE_URL must be an http(s) URL");
    }
    if args.maximum_body_bytes == 0 || args.maximum_body_bytes > 16 * 1024 * 1024 {
        bail!("GATEWAY_MAXIMUM_BODY_BYTES is outside the safe range");
    }
    if !(1..=256).contains(&args.maximum_headers)
        || !(8_192..=128 * 1_024).contains(&args.maximum_header_bytes)
        || !(256..=8 * 1_024).contains(&args.maximum_uri_bytes)
        || !(1..=30).contains(&args.header_timeout_seconds)
        || !(1..=60).contains(&args.body_timeout_seconds)
        || !(1..=3_600).contains(&args.upstream_timeout_seconds)
        || !(1..=300).contains(&args.stream_idle_timeout_seconds)
        || !(1..=4_096).contains(&args.global_request_concurrency)
        || !(1..=256).contains(&args.per_address_concurrency)
        || !(1..=1_024).contains(&args.inference_concurrency)
        || args.inference_queue > 4_096
        || !(1..=30).contains(&args.queue_timeout_seconds)
        || !(1..=128).contains(&args.per_key_concurrency)
        || !(1..=64).contains(&args.attestation_concurrency)
        || !(1..=10_000).contains(&args.requests_per_address_per_second)
    {
        bail!("the public protection limits are outside the safe range");
    }
    if args.state_absence_policy != "fail-closed" {
        bail!("GATEWAY_STATE_ABSENCE_POLICY must be fail-closed");
    }
    if !(1..=300).contains(&args.state_startup_timeout_seconds) {
        bail!("GATEWAY_STATE_STARTUP_TIMEOUT_SECONDS is outside the safe range");
    }
    if args.attestation_timeout_seconds == 0
        || args.attestation_timeout_seconds > 120
        || !(1_024..=8 * 1_024 * 1_024).contains(&args.attestation_maximum_evidence_bytes)
    {
        bail!("the attestation client limits are outside the safe range");
    }
    if args.model.is_empty() || args.model.len() > 256 {
        bail!("GATEWAY_MODEL must identify one configured model");
    }
    if args.c8s_attestation_protocol != PINNED_C8S_ATTESTATION_PROTOCOL {
        bail!(
            "GATEWAY_C8S_ATTESTATION_PROTOCOL must be {PINNED_C8S_ATTESTATION_PROTOCOL}: this build speaks {C8S_ATTESTATION_PROTOCOL} and runs in lockstep with c8s {C8S_ATTESTATION_PROTOCOL_COMMIT}"
        );
    }
    C8sAttestationProvider::from_config(C8sAttestationConfig {
        targets: &args.c8s_receipt_targets,
        evidence_base_url: &args.c8s_evidence_base_url,
        release_id: &args.release_id,
        release_bundle_sha256: &args.release_bundle_sha256,
        expected_operator_public_key_sha256: &args.expected_operator_public_key_sha256,
        expected_operator_key_set_sha256: &args.expected_operator_key_set_sha256,
        policy_mode: &args.c8s_policy_mode,
        expected_static_allowlist_sha256: &args.expected_static_allowlist_sha256,
        timeout: Duration::from_secs(args.attestation_timeout_seconds),
        maximum_receipt_bytes: args.attestation_maximum_evidence_bytes,
    })
    .map_err(anyhow::Error::msg)
    .context("validate the c8s receipt targets")?;
    Ok(())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit as u64 {
        bail!("the mounted file has an unsafe shape");
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn wait_for_bounded_file(path: &Path, limit: usize, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match fs::symlink_metadata(path) {
            Ok(_) => return read_bounded(path, limit),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", path.display()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            listen: "0.0.0.0:9443".parse().unwrap_or_else(|_| unreachable!()),
            metrics_listen: "0.0.0.0:9090".parse().unwrap_or_else(|_| unreachable!()),
            inference_url: INFERENCE_UPSTREAM_URL.to_owned(),
            allow_direct_inference_url: false,
            model: "deepseek-ai/DeepSeek-V4-Flash-0731".to_owned(),
            c8s_receipt_targets: "gateway|gateway|gateway=http://127.0.0.1:8800,sglang-router|sglang-router|sglang-router=http://sglang-router:8801,inference-worker-0|inference-worker-0|inference-worker=http://inference-worker-0-0.inference-workers:8802,inference-worker-1|inference-worker-1|inference-worker=http://inference-worker-1-0.inference-workers:8802,metrics-collector|metrics-collector|metrics-collector=http://metrics-collector:8803,kube-state-metrics|kube-state-metrics|kube-state-metrics=http://kube-state-metrics:8804".to_owned(),
            c8s_evidence_base_url: "https://api.example.test".to_owned(),
            release_id: "test-release".to_owned(),
            release_bundle_sha256: format!("sha256:{}", "1".repeat(64)),
            expected_operator_public_key_sha256: format!("sha256:{}", "2".repeat(64)),
            expected_operator_key_set_sha256: format!("sha256:{}", "3".repeat(64)),
            c8s_policy_mode: "operator".to_owned(),
            c8s_attestation_protocol: PINNED_C8S_ATTESTATION_PROTOCOL.to_owned(),
            expected_static_allowlist_sha256: String::new(),
            attestation_timeout_seconds: 30,
            attestation_maximum_evidence_bytes: 1_048_576,
            environment: "production".to_owned(),
            state_database: PathBuf::from("/var/lib/confidential-gateway/gateway.sqlite3"),
            state_disk_serial: "confai-gateway-state".to_owned(),
            state_absence_policy: "fail-closed".to_owned(),
            state_enabled: false,
            api_key_pepper_file: PathBuf::from("/run/c8s/secrets/GATEWAY_API_KEY_PEPPER"),
            state_startup_timeout_seconds: 60,
            admin_signer_certificate_file: PathBuf::from(
                "/run/confidential-inference/admin-auth/client.crt",
            ),
            maximum_body_bytes: 2_097_152,
            upstream_timeout_seconds: 900,
            maximum_headers: 64,
            maximum_header_bytes: 16_384,
            maximum_uri_bytes: 2_048,
            header_timeout_seconds: 5,
            body_timeout_seconds: 10,
            stream_idle_timeout_seconds: 60,
            global_request_concurrency: 256,
            per_address_concurrency: 16,
            inference_concurrency: 64,
            inference_queue: 64,
            queue_timeout_seconds: 2,
            per_key_concurrency: 4,
            attestation_concurrency: 4,
            requests_per_address_per_second: 30,
            shutdown_grace_seconds: 900,
            endpoint_drain_seconds: 35,
            trusted_proxy_cidrs: Vec::new(),
        }
    }

    #[test]
    fn kubernetes_ports_and_internal_upstream_pass() {
        assert!(validate_args(&args()).is_ok());
    }

    #[test]
    fn only_the_pinned_internal_upstream_is_accepted() {
        let mut value = args();
        for invalid in [
            "http://attacker.example:30000",
            "http://sglang-router-alt:30000",
            "http://127.0.0.1:30000",
            "http://sglang-router:30001",
            "http://sglang-router:30000/v1",
            "http://user:credential@sglang-router:30000",
            "https://sglang-router:30000",
        ] {
            value.inference_url = invalid.to_owned();
            assert!(validate_args(&value).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn custom_environment_and_receipt_target_contract_pass() {
        let mut value = args();
        value.environment = "staging".to_owned();
        value.model = "staging-simulator".to_owned();
        value.c8s_receipt_targets = "gateway|gateway|gateway=http://127.0.0.1:8800,sglang-router|sglang-router|sglang-router=http://sglang-router:8801,inference-worker-0|inference-worker-0|inference-worker-0=http://inference-worker-0-0.inference-workers:8802,inference-worker-1|inference-worker-1|inference-worker-1=http://inference-worker-1-0.inference-workers:8802".to_owned();
        assert!(validate_args(&value).is_ok());
    }

    #[test]
    fn configured_environment_accepts_its_explicit_model() {
        let mut value = args();
        value.environment = "staging".to_owned();
        value.c8s_receipt_targets = "gateway|gateway|gateway=http://127.0.0.1:8800,sglang-router|sglang-router|sglang-router=http://sglang-router:8801,inference-worker-0|inference-worker-0|inference-worker-0=http://inference-worker-0-0.inference-workers:8802,inference-worker-1|inference-worker-1|inference-worker-1=http://inference-worker-1-0.inference-workers:8802".to_owned();
        assert!(validate_args(&value).is_ok());
    }

    #[test]
    fn non_proxy_inference_url_requires_the_explicit_escape() {
        let mut value = args();
        value.inference_url = "http://sglang-router:30000".to_owned();
        assert!(validate_args(&value).is_err());
        value.allow_direct_inference_url = true;
        assert!(validate_args(&value).is_ok());
        value.inference_url = "sglang-router:30000".to_owned();
        assert!(validate_args(&value).is_err());
    }

    #[test]
    fn only_the_pinned_c8s_attestation_protocol_is_accepted() {
        let mut value = args();
        assert!(validate_args(&value).is_ok());
        value.c8s_attestation_protocol = "v1-session-pubkey".to_owned();
        assert!(validate_args(&value).is_err());
        value.c8s_attestation_protocol = String::new();
        assert!(validate_args(&value).is_err());
    }

    #[test]
    fn invalid_environment_name_fails() {
        let mut value = args();
        value.environment = "Invalid Environment".to_owned();
        assert!(validate_args(&value).is_err());
    }

    #[test]
    fn unsafe_state_and_attestation_configuration_fail() {
        let mut value = args();
        value.state_absence_policy = "create-empty".to_owned();
        assert!(validate_args(&value).is_err());
        value.state_absence_policy = "fail-closed".to_owned();
        value.c8s_receipt_targets =
            "gateway|gateway|gateway=https://attestation.example:8800".to_owned();
        assert!(validate_args(&value).is_err());
    }

    #[test]
    fn absent_state_inputs_fail_closed() {
        let missing = PathBuf::from("/definitely-absent/confidential-gateway/state");
        assert!(read_bounded(&missing, 4_096).is_err());
    }

    #[test]
    fn delayed_c8s_secret_is_accepted_within_the_startup_window() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let path = directory.path().join("pepper");
        let writer = path.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            fs::write(writer, b"staging-pepper").unwrap_or_else(|_| unreachable!());
        });
        let value = wait_for_bounded_file(&path, 4_096, Duration::from_secs(2))
            .unwrap_or_else(|_| unreachable!());
        handle.join().unwrap_or_else(|_| unreachable!());
        assert_eq!(value, b"staging-pepper");
    }

    #[test]
    fn absent_c8s_secret_fails_after_the_startup_window() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let path = directory.path().join("pepper");
        assert!(wait_for_bounded_file(&path, 4_096, Duration::from_millis(100)).is_err());
    }
}
