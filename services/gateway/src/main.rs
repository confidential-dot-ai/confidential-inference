//! Kubernetes process wiring for the confidential inference gateway.

use std::{
    fs,
    io::Read,
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
    admin_auth::{
        AdminRequestVerifier, MAX_API_KEY_HASHES_BYTES, MAX_CERTIFICATE_BYTES,
        require_signed_admin_request,
    },
    admin_client::{self, AdminClient},
    api_keys::{KeyStore, admin_router},
    metrics::{GatewayMetrics, metrics_router},
    protection::ProtectionConfig,
    router_with_usage,
    settings::GatewaySettings,
};
use hyper_util::rt::{TokioExecutor, TokioTimer};

// The gateway must never dial the router Service directly. The c8s
// workload-proxy client owns this loopback port and provides the authenticated
// hop to the named router workload.
const INFERENCE_UPSTREAM_URL: &str = "http://127.0.0.1:30001";
// Inside the termination grace the chart leaves after the HTTP drain.
const USAGE_FLUSH_TIMEOUT: Duration = Duration::from_secs(20);

/// The only field of the admin client secret the gateway reads.
#[derive(serde::Deserialize)]
struct AdminSecret {
    token: String,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "confidential-gateway")]
struct Args {
    // The admin client token: a CDS secret, JSON `{"token": ...}`
    // (`crate::admin_client`). Other fields of the secret are ignored.
    #[arg(
        long,
        env = "GATEWAY_ADMIN_CONFIG_FILE",
        default_value = "/run/c8s/secrets/product-usage"
    )]
    admin_config_file: PathBuf,
    // Where the key pull and usage events go, and which models usage is
    // recorded for. They are environment, so the allowlist pins them: the
    // control plane cannot point the gateway's exit at anything else.
    #[arg(long, env = "GATEWAY_ADMIN_ENDPOINT", default_value = "")]
    admin_endpoint: String,
    #[arg(long, env = "GATEWAY_USAGE_MODELS", default_value = "{}")]
    usage_models: String,
    #[arg(long, env = "GATEWAY_USAGE_ENABLED", default_value_t = false)]
    usage_enabled: bool,
    #[arg(long, env = "GATEWAY_ROUTER_NAMESPACE")]
    router_namespace: Option<String>,
    // The chart's settings ConfigMap, read once at start. Its values replace
    // the matching arguments below.
    #[arg(long, env = "GATEWAY_RUNTIME_CONFIG_FILE")]
    runtime_config_file: Option<PathBuf>,
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
    #[arg(long, env = "GATEWAY_MODEL", default_value = "")]
    model: String,
    #[arg(long, env = "GATEWAY_INSTANCE_ID")]
    gateway_instance_id: Option<String>,
    #[arg(long, env = "DEPLOYMENT_ENVIRONMENT")]
    environment: String,
    #[arg(
        long,
        env = "GATEWAY_API_KEY_PEPPER_FILE",
        default_value = "/run/c8s/secrets/GATEWAY_API_KEY_PEPPER"
    )]
    api_key_pepper_file: PathBuf,
    // c8s writes the secrets after the container starts.
    #[arg(long, env = "GATEWAY_SECRET_WAIT_SECONDS", default_value_t = 300)]
    secret_wait_seconds: u64,
    #[arg(
        long,
        env = "GATEWAY_ADMIN_SIGNER_CERTIFICATE_FILE",
        default_value = "/mnt/c8s-data/admin-auth/client.crt"
    )]
    admin_signer_certificate_file: PathBuf,
    // SHA-256 of the accepted admin API keys, from the Kubernetes Secret
    // gateway-admin-api-key. A missing file accepts only the v1 signature
    // until the admin cutover (#186).
    #[arg(
        long,
        env = "GATEWAY_ADMIN_API_KEY_HASHES_FILE",
        default_value = "/mnt/c8s-data/admin-api-key/sha256"
    )]
    admin_api_key_hashes_file: PathBuf,
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
    let log_export = std::env::var("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
        .ok()
        .map(otlp_log_export)
        .transpose()?;
    {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .with(log_export.as_ref().map(otlp_log_layer))
            .init();
    }
    let mut args = Args::parse();
    // The HTTP/2 stream limit keeps the startup argument; the settings file
    // does not change it.
    let limits = HttpLimits::from_args(&args)?;
    let mut catalog_model_ids = vec![args.model.clone()];
    let mut inference_model_ids = vec![args.model.clone()];
    if let Some(path) = args.runtime_config_file.clone() {
        let settings: GatewaySettings = serde_json::from_slice(&read_bounded(&path, 256 * 1024)?)
            .context("parse the gateway settings")?;
        apply_settings(&mut args, &settings).context("load gateway settings")?;
        catalog_model_ids = settings.catalog_model_ids;
        inference_model_ids = settings.inference_model_ids;
    }
    validate_args(&args)?;
    tracing::info!("gateway configuration validated");

    let secret_wait = Duration::from_secs(args.secret_wait_seconds);
    let metrics = Arc::new(GatewayMetrics::new(args.environment.clone()));
    let pepper = wait_for_bounded_file(&args.api_key_pepper_file, 4_096, secret_wait)?;
    let keys = Arc::new(
        KeyStore::new(pepper, &args.environment)
            .map_err(|_| anyhow::anyhow!("the API key pepper must be at least 32 bytes"))?
            .with_metrics(metrics.clone()),
    );
    let secret: AdminSecret = serde_json::from_slice(&wait_for_bounded_file(
        &args.admin_config_file,
        65_536,
        secret_wait,
    )?)
    .context("invalid admin client secret")?;
    let admin_config = admin_client::Config {
        endpoint: args.admin_endpoint.clone(),
        token: secret.token,
        tls_ca_pem: None,
        connect_address: None,
        models: serde_json::from_str(&args.usage_models).context("invalid GATEWAY_USAGE_MODELS")?,
    };
    let admin = Arc::new(AdminClient::new(&admin_config).map_err(anyhow::Error::msg)?);
    tokio::spawn(admin_client::sync_keys(
        admin.clone(),
        keys.clone(),
        metrics.clone(),
    ));
    let timeout = Duration::from_secs(args.upstream_timeout_seconds);
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build the internal inference client")?;
    let protection = protection_config(&args);
    let usage = args.usage_enabled.then(|| {
        // Each process is one producer instance; the pod hostname is fixed.
        let instance = format!("gateway-{}", uuid::Uuid::new_v4().simple());
        let recorder = confidential_gateway::usage::Recorder::new(
            &instance,
            admin_config.models.clone(),
            confidential_gateway::usage::MAX_PENDING_EVENTS,
            metrics.clone(),
        );
        tokio::spawn(recorder.clone().deliver(admin.clone()));
        recorder
    });
    let public = router_with_usage(
        GatewayConfig {
            catalog_model_ids,
            inference_model_ids,
            upstream_base_url: args.inference_url.trim_end_matches('/').to_owned(),
            maximum_body_bytes: args.maximum_body_bytes,
            upstream_timeout: timeout,
            protection,
        },
        keys.clone(),
        Arc::new(TracingAuditSink),
        metrics.clone(),
        http,
        usage.clone(),
    );
    let public = with_instance_header(public, args.gateway_instance_id.as_deref())?;
    let admin_certificate =
        read_bounded(&args.admin_signer_certificate_file, MAX_CERTIFICATE_BYTES)
            .context("read the admin request signer certificate")?;
    let mut admin_verifier = AdminRequestVerifier::from_certificate_pem(&admin_certificate)
        .map_err(anyhow::Error::msg)
        .context("parse the admin request signer certificate")?;
    if args.admin_api_key_hashes_file.exists() {
        let hashes = read_bounded(&args.admin_api_key_hashes_file, MAX_API_KEY_HASHES_BYTES)
            .context("read the admin API key hashes")?;
        admin_verifier = admin_verifier
            .with_api_key_hashes(&hashes)
            .map_err(anyhow::Error::msg)
            .context("parse the admin API key hashes")?;
    } else {
        tracing::info!("no admin API key file; admin requests need the v1 signature");
    }
    let admin_routes = admin_router(keys).layer(middleware::from_fn_with_state(
        admin_verifier,
        require_signed_admin_request,
    ));
    let app = public.merge(admin_routes);

    let metrics_listener = tokio::net::TcpListener::bind(args.metrics_listen)
        .await
        .context("bind the private metrics listener")?;
    let private = metrics_router(metrics);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(metrics_listener, private).await {
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
    limits.apply(public_server.http_builder());
    public_server
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .context("serve the public gateway")?;
    // Every request has finished, so every usage event is queued.
    if let Some(usage) = usage {
        usage.flush(&admin, USAGE_FLUSH_TIMEOUT).await;
    }
    if let Some(log_export) = log_export {
        let _ = tokio::task::spawn_blocking(move || log_export.shutdown()).await;
    }
    Ok(())
}

/// Log export to the telemetry collector over OTLP/HTTP, on when the standard
/// `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` is set. The SDK reads
/// `OTEL_SERVICE_NAME`; both variables are pinned in the allowlist.
fn otlp_log_export(endpoint: String) -> Result<opentelemetry_sdk::logs::SdkLoggerProvider> {
    use opentelemetry_otlp::WithExportConfig;
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .build()
        .context("build the OTLP log exporter")?;
    Ok(opentelemetry_sdk::logs::SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .build())
}

/// The layer that hands gateway log events to the OTLP provider. The
/// exporter's own HTTP stack stays out, so an export never logs itself.
fn otlp_log_layer<S>(
    provider: &opentelemetry_sdk::logs::SdkLoggerProvider,
) -> impl tracing_subscriber::Layer<S>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    use tracing_subscriber::Layer;
    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider).with_filter(
        tracing_subscriber::filter::filter_fn(|metadata| {
            !["opentelemetry", "reqwest", "hyper", "h2", "tower"]
                .iter()
                .any(|target| metadata.target().starts_with(target))
        }),
    )
}

/// HTTP limits of the public listener.
struct HttpLimits {
    header_timeout: Duration,
    maximum_headers: usize,
    maximum_buffer: usize,
    h2_streams: u32,
    h2_header_bytes: u32,
}

impl HttpLimits {
    fn from_args(args: &Args) -> Result<Self> {
        Ok(Self {
            header_timeout: Duration::from_secs(args.header_timeout_seconds),
            maximum_headers: args.maximum_headers,
            maximum_buffer: args.maximum_header_bytes.max(8_192),
            h2_streams: u32::try_from(args.inference_concurrency)
                .context("convert the HTTP/2 stream limit")?,
            h2_header_bytes: u32::try_from(args.maximum_header_bytes)
                .context("convert the HTTP/2 header limit")?,
        })
    }

    fn apply(&self, builder: &mut hyper_util::server::conn::auto::Builder<TokioExecutor>) {
        builder
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(self.header_timeout)
            .max_headers(self.maximum_headers)
            .max_buf_size(self.maximum_buffer);
        builder
            .http2()
            .max_concurrent_streams(self.h2_streams)
            .max_header_list_size(self.h2_header_bytes);
    }
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
        requests_per_address_per_second: args.requests_per_address_per_second,
        trusted_proxy_cidrs: args.trusted_proxy_cidrs.clone(),
    }
}

fn with_instance_header(app: axum::Router, identity: Option<&str>) -> Result<axum::Router> {
    let Some(identity) = identity else {
        return Ok(app);
    };
    if identity.is_empty()
        || identity.len() > 63
        || identity.starts_with('-')
        || identity.ends_with('-')
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("GATEWAY_INSTANCE_ID must be a DNS label");
    }
    let header: axum::http::HeaderValue = identity.parse()?;
    Ok(app.layer(middleware::map_response(
        move |mut response: axum::response::Response| {
            let header = header.clone();
            async move {
                response
                    .headers_mut()
                    .insert("x-confidential-gateway", header);
                response
            }
        },
    )))
}

fn validate_router_namespace(namespace: Option<&str>, inference_url: &str) -> Result<()> {
    if namespace.is_some_and(|name| {
        name.is_empty()
            || name.len() > 63
            || name.starts_with('-')
            || name.ends_with('-')
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    }) {
        bail!("GATEWAY_ROUTER_NAMESPACE must be a namespace name");
    }
    if namespace.is_some() {
        let origin = url::Url::parse(inference_url).context("parse the fixed router origin")?;
        if !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || origin.path() != "/"
        {
            bail!("the fixed router origin must have no credentials, query, fragment, or path");
        }
    }
    Ok(())
}

fn validate_args(args: &Args) -> Result<()> {
    validate_router_namespace(args.router_namespace.as_deref(), &args.inference_url)?;
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
    if !(1024..=confidential_gateway::MAXIMUM_BODY_BYTES_CEILING).contains(&args.maximum_body_bytes)
    {
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
        || !(1..=10_000).contains(&args.requests_per_address_per_second)
    {
        bail!("the public protection limits are outside the safe range");
    }
    if !(1..=600).contains(&args.secret_wait_seconds) {
        bail!("GATEWAY_SECRET_WAIT_SECONDS is outside the safe range");
    }
    if args.model.is_empty() || args.model.len() > 256 {
        bail!("GATEWAY_MODEL must identify one configured model");
    }
    Ok(())
}

/// Replace the matching arguments with the settings file. `validate_args`
/// then bounds the numeric values.
fn apply_settings(args: &mut Args, settings: &GatewaySettings) -> Result<()> {
    settings.validate().map_err(anyhow::Error::msg)?;
    if let Some(service) = &settings.router_service {
        let (Some(namespace), true) = (&args.router_namespace, args.allow_direct_inference_url)
        else {
            bail!("a router Service needs the fixed namespace and direct-router mode");
        };
        validate_router_namespace(Some(namespace), &args.inference_url)?;
        // The namespace and port are startup trust inputs. The settings can
        // select only a router Service in this namespace.
        let origin = url::Url::parse(&args.inference_url)?;
        let port = origin
            .port_or_known_default()
            .context("the fixed router origin has no port")?;
        args.inference_url = format!(
            "{}://{service}.{namespace}.svc.cluster.local:{port}",
            origin.scheme()
        );
    }
    args.model = settings
        .inference_model_ids
        .first()
        .cloned()
        .unwrap_or_default();
    args.maximum_body_bytes = settings.maximum_body_bytes;
    args.upstream_timeout_seconds = settings.upstream_timeout_seconds;
    args.body_timeout_seconds = settings.body_timeout_seconds;
    args.stream_idle_timeout_seconds = settings.stream_idle_timeout_seconds;
    args.global_request_concurrency = settings.global_request_concurrency;
    args.per_address_concurrency = settings.per_address_concurrency;
    args.inference_concurrency = settings.inference_concurrency;
    args.inference_queue = settings.inference_queue;
    args.queue_timeout_seconds = settings.queue_timeout_seconds;
    args.per_key_concurrency = settings.per_key_concurrency;
    args.requests_per_address_per_second = settings.requests_per_address_per_second;
    Ok(())
}

// Kubernetes directory mounts expose each file as a symlink into the kubelet
// atomic-writer directory, such as `<dir>/file -> ..data/file` with
// `..data -> ..<timestamp>`. A symlink is accepted only when its canonical
// target stays inside the canonical directory of the configured path and is a
// non-empty regular file within the limit. The bytes come from one opened
// handle, so the checked file is the file that is read.
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolve {}", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let directory = fs::canonicalize(directory)
        .with_context(|| format!("resolve the directory of {}", path.display()))?;
    if canonical == directory || !canonical.starts_with(&directory) {
        bail!("the mounted file resolves outside its directory");
    }
    // The canonical path has no symlinks left. Check its shape before the open
    // so a FIFO or device is never opened, then check the opened handle again.
    let unsafe_shape = |metadata: &fs::Metadata| {
        !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > limit as u64
    };
    let metadata = fs::symlink_metadata(&canonical)
        .with_context(|| format!("inspect {}", canonical.display()))?;
    if unsafe_shape(&metadata) {
        bail!("the mounted file has an unsafe shape");
    }
    let file =
        fs::File::open(&canonical).with_context(|| format!("open {}", canonical.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {}", canonical.display()))?;
    if unsafe_shape(&metadata) {
        bail!("the mounted file has an unsafe shape");
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", canonical.display()))?;
    if bytes.is_empty() || bytes.len() > limit {
        bail!("the mounted file has an unsafe shape");
    }
    Ok(bytes)
}

// The probe follows symlinks, so a kubelet symlink whose target does not exist
// yet is retried like a missing file.
fn wait_for_bounded_file(path: &Path, limit: usize, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match fs::metadata(path) {
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

    fn settings(router_service: Option<&str>) -> GatewaySettings {
        let mut value = serde_json::json!({
            "schemaVersion":1,"evidence":{"baseUrl":"https://candidate.example.test"},
            "catalogModelIds":["test"],"inferenceModelIds":["test"],"maximumBodyBytes":1024,
            "upstreamTimeoutSeconds":30,"bodyTimeoutSeconds":10,"streamIdleTimeoutSeconds":20,
            "attestationCacheSeconds":3,"globalRequestConcurrency":256,"perAddressConcurrency":16,
            "inferenceConcurrency":1,"inferenceQueue":0,"queueTimeoutSeconds":2,"perKeyConcurrency":4,
            "attestationConcurrency":4,"requestsPerAddressPerSecond":30
        });
        if let Some(service) = router_service {
            value["routerService"] = service.into();
        }
        serde_json::from_value(value).unwrap_or_else(|_| unreachable!())
    }

    #[test]
    fn settings_replace_the_matching_arguments() -> Result<()> {
        let mut value = args();
        value.inference_url = "http://sglang-router:30000".into();
        value.allow_direct_inference_url = true;
        value.router_namespace = Some("confidential-inference".into());
        apply_settings(&mut value, &settings(Some("router-headless")))?;
        assert_eq!(
            value.inference_url,
            "http://router-headless.confidential-inference.svc.cluster.local:30000"
        );
        assert_eq!(value.model, "test");
        assert_eq!(value.inference_concurrency, 1);
        validate_args(&value)?;
        // The settings cannot raise a limit past the argument bounds.
        let mut limits = settings(None);
        limits.per_key_concurrency = 4096;
        let mut value = args();
        apply_settings(&mut value, &limits)?;
        assert!(validate_args(&value).is_err());
        Ok(())
    }

    #[test]
    fn settings_need_a_fixed_router_namespace() {
        let mut value = args();
        assert!(apply_settings(&mut value, &settings(Some("router-headless"))).is_err());
        value.allow_direct_inference_url = true;
        value.inference_url = "http://sglang-router:30000".into();
        assert!(apply_settings(&mut value, &settings(Some("router-headless"))).is_err());
        value.router_namespace = Some("confidential-inference".into());
        assert!(apply_settings(&mut value, &settings(Some("other"))).is_err());
        assert!(apply_settings(&mut value, &settings(Some("router-headless"))).is_ok());
    }

    #[tokio::test]
    async fn instance_header_identifies_the_slot_without_changing_the_body() -> Result<()> {
        use tower::ServiceExt as _;
        let app = axum::Router::new().route("/health", axum::routing::get(|| async { "metadata" }));
        let app = with_instance_header(app, Some("gateway-new"))?;
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .header("x-confidential-gateway", "caller-controlled")
                    .body(axum::body::Body::empty())?,
            )
            .await?;
        assert_eq!(response.headers()["x-confidential-gateway"], "gateway-new");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 1024).await?,
            "metadata"
        );
        for bad in ["", "-bad", "bad-", "a\r\nb", "Uppercase"] {
            assert!(with_instance_header(axum::Router::new(), Some(bad)).is_err());
        }
        Ok(())
    }

    fn args() -> Args {
        Args {
            admin_config_file: PathBuf::from("/run/c8s/secrets/product-usage"),
            admin_endpoint: "https://admin.example.com/api/usage/ingest".into(),
            usage_models: "{}".into(),
            usage_enabled: false,
            router_namespace: None,
            runtime_config_file: None,
            listen: "0.0.0.0:9443".parse().unwrap_or_else(|_| unreachable!()),
            metrics_listen: "0.0.0.0:9090".parse().unwrap_or_else(|_| unreachable!()),
            inference_url: INFERENCE_UPSTREAM_URL.to_owned(),
            allow_direct_inference_url: false,
            model: "deepseek-ai/DeepSeek-V4-Flash-0731".to_owned(),
            gateway_instance_id: None,
            environment: "production".to_owned(),
            api_key_pepper_file: PathBuf::from("/run/c8s/secrets/GATEWAY_API_KEY_PEPPER"),
            secret_wait_seconds: 300,
            admin_signer_certificate_file: PathBuf::from("/mnt/c8s-data/admin-auth/client.crt"),
            admin_api_key_hashes_file: PathBuf::from("/mnt/c8s-data/admin-api-key/sha256"),
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
    fn custom_environment_and_model_pass() {
        let mut value = args();
        value.environment = "staging".to_owned();
        value.model = "staging-simulator".to_owned();
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
    fn invalid_environment_name_fails() {
        let mut value = args();
        value.environment = "Invalid Environment".to_owned();
        assert!(validate_args(&value).is_err());
    }

    #[test]
    fn unsafe_secret_wait_fails() {
        let mut value = args();
        value.secret_wait_seconds = 0;
        assert!(validate_args(&value).is_err());
    }

    #[test]
    fn absent_mounted_inputs_fail_closed() {
        let missing = PathBuf::from("/definitely-absent/confidential-gateway/pepper");
        assert!(read_bounded(&missing, 4_096).is_err());
    }

    // Build the kubelet atomic-writer layout: `<dir>/..2026_x/<name>`, then
    // `<dir>/..data -> ..2026_x` and `<dir>/<name> -> ..data/<name>`.
    #[cfg(unix)]
    /// Lay out a kubelet atomic-writer mount: `name` -> `..data/name`, and
    /// `..data` -> a timestamped directory that holds the file.
    #[cfg(unix)]
    fn kubelet_mount(directory: &Path, name: &str, contents: &[u8]) -> PathBuf {
        kubelet_data(directory, name, contents);
        kubelet_link(directory, name)
    }

    #[cfg(unix)]
    fn kubelet_data(directory: &Path, name: &str, contents: &[u8]) {
        let timestamped = directory.join("..2026_10_01_00_00_00.000000000");
        fs::create_dir(&timestamped).unwrap_or_else(|_| unreachable!());
        fs::write(timestamped.join(name), contents).unwrap_or_else(|_| unreachable!());
        std::os::unix::fs::symlink("..2026_10_01_00_00_00.000000000", directory.join("..data"))
            .unwrap_or_else(|_| unreachable!());
    }

    #[cfg(unix)]
    fn kubelet_link(directory: &Path, name: &str) -> PathBuf {
        let path = directory.join(name);
        std::os::unix::fs::symlink(Path::new("..data").join(name), &path)
            .unwrap_or_else(|_| unreachable!());
        path
    }

    #[test]
    #[cfg(unix)]
    fn kubelet_symlinked_file_is_accepted() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let path = kubelet_mount(directory.path(), "pepper", b"identity");
        let value = read_bounded(&path, 4_096).unwrap_or_else(|_| unreachable!());
        assert_eq!(value, b"identity");
    }

    #[test]
    #[cfg(unix)]
    fn kubelet_symlinked_file_over_the_limit_fails() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let path = kubelet_mount(directory.path(), "pepper", &[b'x'; 4_097]);
        assert!(read_bounded(&path, 4_096).is_err());
        assert!(read_bounded(&path, 4_097).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn symlink_outside_the_mount_directory_fails() {
        let root = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let target = root.path().join("secret");
        fs::write(&target, b"outside").unwrap_or_else(|_| unreachable!());
        let directory = root.path().join("mount");
        fs::create_dir(&directory).unwrap_or_else(|_| unreachable!());
        let absolute = directory.join("absolute");
        std::os::unix::fs::symlink(&target, &absolute).unwrap_or_else(|_| unreachable!());
        assert!(read_bounded(&absolute, 4_096).is_err());
        let relative = directory.join("relative");
        std::os::unix::fs::symlink(Path::new("..").join("secret"), &relative)
            .unwrap_or_else(|_| unreachable!());
        assert!(read_bounded(&relative, 4_096).is_err());
        assert!(read_bounded(&target, 4_096).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn symlink_to_a_directory_fails() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let inner = directory.path().join("..data");
        fs::create_dir(&inner).unwrap_or_else(|_| unreachable!());
        let path = directory.path().join("pepper");
        std::os::unix::fs::symlink("..data", &path).unwrap_or_else(|_| unreachable!());
        assert!(read_bounded(&path, 4_096).is_err());
        assert!(read_bounded(directory.path(), 4_096).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn dangling_kubelet_symlink_is_retried_until_the_target_appears() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let path = kubelet_link(directory.path(), "pepper");
        let mount = directory.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            kubelet_data(&mount, "pepper", b"staging-pepper");
        });
        let value = wait_for_bounded_file(&path, 4_096, Duration::from_secs(2))
            .unwrap_or_else(|_| unreachable!());
        handle.join().unwrap_or_else(|_| unreachable!());
        assert_eq!(value, b"staging-pepper");
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

#[cfg(test)]
mod otlp_log_tests {
    use anyhow::{Context, Result, anyhow};
    use std::io::{BufRead, BufReader, Read, Write};
    use tracing_subscriber::layer::SubscriberExt;

    /// One OTLP/HTTP request: its path and body.
    fn receive_one(listener: &std::net::TcpListener) -> Result<(String, Vec<u8>)> {
        let (stream, _) = listener.accept()?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let path = line.split(' ').nth(1).context("request line")?.to_owned();
        let mut length = 0;
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse()?;
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body)?;
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")?;
        Ok((path, body))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_log_event_reaches_the_otlp_endpoint() -> Result<()> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = format!("http://{}/v1/logs", listener.local_addr()?);
        let server = std::thread::spawn(move || receive_one(&listener));
        let provider = super::otlp_log_export(endpoint)?;
        let subscriber = tracing_subscriber::registry().with(super::otlp_log_layer(&provider));
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("gateway otlp test line");
        });
        tokio::task::spawn_blocking(move || provider.shutdown()).await??;
        let (path, body) = server
            .join()
            .map_err(|_| anyhow!("the OTLP test server panicked"))??;
        assert_eq!(path, "/v1/logs");
        let needle = b"gateway otlp test line";
        assert!(body.windows(needle.len()).any(|window| window == needle));
        Ok(())
    }
}
