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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .compact()
        .init();
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
