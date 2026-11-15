use std::{net::SocketAddr, time::Duration};

use anyhow::{Context as _, Result, bail};
use axum_server::Handle;
use clap::Parser;
use hyper_util::rt::TokioTimer;
use maintenance_gateway::{ProtectionConfig, app_with_config};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct Args {
    #[arg(
        long,
        env = "MAINTENANCE_GATEWAY_LISTEN",
        default_value = "0.0.0.0:9443"
    )]
    listen: SocketAddr,
    #[arg(
        long,
        env = "MAINTENANCE_GATEWAY_TRUSTED_PROXY_CIDRS",
        value_delimiter = ','
    )]
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
}

/// `RUST_LOG` cannot open the HTTP libraries' debug output: at `debug` and
/// `trace` they can print headers and request text.
fn log_allowed(metadata: &tracing::Metadata<'_>) -> bool {
    let http = [
        "hyper",
        "hyper_util",
        "h2",
        "tower",
        "axum",
        "axum_server",
        "rustls",
    ]
    .iter()
    .any(|prefix| {
        metadata
            .target()
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with("::"))
    });
    !http || *metadata.level() <= tracing::Level::WARN
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{Layer as _, layer::SubscriberExt, util::SubscriberInitExt};
        tracing_subscriber::registry()
            .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .compact()
                    .with_filter(tracing_subscriber::filter::filter_fn(log_allowed)),
            )
            .init();
    }
    // The default hook prints the panic message, which can quote a request.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()))
            .unwrap_or_default();
        tracing::error!(
            location,
            "the maintenance gateway panicked; the message is not logged"
        );
    }));
    let args = Args::parse();
    if args.listen.port() != 9443 {
        bail!("the maintenance gateway must listen on port 9443");
    }
    let handle = Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    });
    tracing::info!(listen = %args.listen, "the maintenance gateway is ready behind c8s TLS-LB");
    let mut server = axum_server::bind(args.listen).handle(handle);
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_headers(64)
        .max_buf_size(16 * 1024);
    server
        .http_builder()
        .http2()
        .max_concurrent_streams(128)
        .max_header_list_size(16 * 1024);
    server
        .serve(
            app_with_config(ProtectionConfig {
                trusted_proxy_cidrs: args.trusted_proxy_cidrs,
            })
            .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .context("serve the maintenance gateway")
}
