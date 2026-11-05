use std::{net::SocketAddr, time::Duration};

use anyhow::{Context as _, Result, bail};
use axum_server::Handle;
use clap::Parser;
use hyper_util::rt::TokioTimer;
use maintenance_gateway::{ProtectionConfig, app_with_config};
use tracing_subscriber::util::SubscriberInitExt;

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
async fn main() -> std::process::ExitCode {
    std::panic::set_hook(Box::new(|_| write_event("maintenance_panic")));
    if run().await.is_ok() {
        std::process::ExitCode::SUCCESS
    } else {
        write_event("maintenance_startup_failed");
        std::process::ExitCode::FAILURE
    }
}

fn write_event(event: &'static str) {
    if !matches!(
        event,
        "maintenance_ready" | "maintenance_startup_failed" | "maintenance_panic"
    ) {
        return;
    }
    let record = serde_json::json!({"schema_version":1,"component":"maintenance","event":event});
    let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("{record}\n").as_bytes());
}

async fn run() -> Result<()> {
    tracing_subscriber::registry().init();
    let args =
        Args::try_parse().map_err(|_| anyhow::anyhow!("invalid maintenance configuration"))?;
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
    write_event("maintenance_ready");
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
