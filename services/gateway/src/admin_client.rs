//! The gateway's HTTPS client to the admin: it pulls the key snapshot and
//! sends usage events.
//!
//! `endpoint` is the admin's usage ingest URL and `models` the models usage is
//! recorded for; the gateway takes both from its pinned environment
//! (`GATEWAY_ADMIN_ENDPOINT`, `GATEWAY_USAGE_MODELS`). The key snapshot is
//! served on the same origin at [`KEY_SNAPSHOT_PATH`]. The URL's host is the
//! TLS name the gateway checks against the image's public roots. `token`, the
//! only field of the CDS secret `/confidential-inference/gateway/product-usage`
//! the gateway reads, authenticates it to the admin, which maps it to one
//! environment and key realm. `tls_ca_pem` and `connect_address` are for
//! tests against a local admin.

use std::{collections::BTreeMap, net::IpAddr, sync::Arc, time::Duration};

use futures_util::StreamExt;
use serde::Deserialize;

use crate::{
    api_keys::KeyStore,
    key_registry::SnapshotPush,
    metrics::GatewayMetrics,
    usage::{Event, Model},
};

/// The admin route that serves the key snapshot of the token's key realm.
pub const KEY_SNAPSHOT_PATH: &str = "/api/gateway/key-snapshot";
/// How often a ready gateway pulls the key snapshot.
pub const KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
/// How often a gateway with no keys yet retries the first pull.
const FIRST_KEY_RETRY_INTERVAL: Duration = Duration::from_secs(5);
/// A snapshot of 10 000 keys is well under this.
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 65_536;

/// Fields of the CDS secret this client reads. Other fields of the secret
/// are ignored.
#[derive(Clone, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub token: String,
    #[serde(default)]
    pub tls_ca_pem: Option<String>,
    /// Connect to this address instead of the address DNS returns. The TLS
    /// name is still the host of `endpoint`.
    #[serde(default)]
    pub connect_address: Option<IpAddr>,
    /// The requested models usage is recorded for, each with the backend
    /// model whose response may supply its token counts.
    #[serde(default)]
    pub models: BTreeMap<String, Model>,
}

/// Why a usage batch was not delivered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    /// The admin refused this batch (status code); it must not be sent again.
    Rejected(u16),
    /// A failure that can pass later (reason code).
    Retry(&'static str),
}

pub struct AdminClient {
    http: reqwest::Client,
    events_url: url::Url,
    key_snapshot_url: url::Url,
    token: String,
}

impl AdminClient {
    /// # Errors
    ///
    /// Returns an error for a URL that is not a plain `https` URL, a token
    /// outside 32 to 256 URL-safe characters, or an invalid CA.
    pub fn new(config: &Config) -> Result<Self, String> {
        let events_url = url::Url::parse(&config.endpoint).map_err(|_| "invalid admin endpoint")?;
        let host = events_url
            .host_str()
            .ok_or("the admin endpoint has no host")?
            .to_owned();
        if events_url.scheme() != "https"
            || !events_url.username().is_empty()
            || events_url.password().is_some()
            || events_url.query().is_some()
            || events_url.fragment().is_some()
        {
            return Err("the admin endpoint must be a plain https URL".into());
        }
        if !(32..=256).contains(&config.token.len())
            || !config
                .token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err("the admin token is invalid".into());
        }
        let mut key_snapshot_url = events_url.clone();
        key_snapshot_url.set_path(KEY_SNAPSHOT_PATH);
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20));
        if let Some(address) = config.connect_address {
            let port = events_url.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(&host, std::net::SocketAddr::new(address, port));
        }
        if let Some(pem) = &config.tls_ca_pem {
            let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|_| "the admin CA is invalid")?;
            builder = builder.tls_certs_only([certificate]);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|_| "the admin client failed to build")?,
            events_url,
            key_snapshot_url,
            token: config.token.clone(),
        })
    }

    /// Fetch the admin's current key snapshot.
    ///
    /// # Errors
    ///
    /// Returns a short reason code for a transport error, a non-200 status,
    /// an oversized body or a body that is not a snapshot.
    pub async fn key_snapshot(&self) -> Result<SnapshotPush, &'static str> {
        let response = self
            .http
            .get(self.key_snapshot_url.clone())
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|_| "unreachable")?;
        if response.status() != reqwest::StatusCode::OK {
            return Err("http_status");
        }
        let body = bounded_body(response, MAX_SNAPSHOT_BYTES).await?;
        serde_json::from_slice(&body).map_err(|_| "invalid_body")
    }

    /// Send one batch of usage events. The admin stores each event once by
    /// its `request_id`, so a batch may be sent again after any failure.
    ///
    /// # Errors
    ///
    /// `SendError::Rejected` when the admin refuses the batch itself (400,
    /// 413, 422): sending it again cannot succeed. `SendError::Retry` for a
    /// transport error or any other status, such as 5xx, 429 or a wrong
    /// token (401), which can succeed later.
    pub async fn send_events(&self, events: &[Event]) -> Result<(), SendError> {
        let response = self
            .http
            .post(self.events_url.clone())
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "events": events }))
            .send()
            .await
            .map_err(|_| SendError::Retry("unreachable"))?;
        let status = response.status();
        if matches!(status.as_u16(), 400 | 413 | 422) {
            return Err(SendError::Rejected(status.as_u16()));
        }
        if !status.is_success() {
            return Err(SendError::Retry("http_status"));
        }
        bounded_body(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(SendError::Retry)?;
        Ok(())
    }
}

async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>, &'static str> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err("body_too_large");
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "unreachable")?;
        if body.len() + chunk.len() > limit {
            return Err("body_too_large");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Pull the key snapshot until the process stops: every 5 s until the first
/// snapshot is applied, then every 30 s. A failed pull keeps the cache the
/// gateway already holds.
pub async fn sync_keys(
    client: Arc<AdminClient>,
    store: Arc<KeyStore>,
    metrics: Arc<GatewayMetrics>,
) {
    loop {
        match client.key_snapshot().await {
            Ok(snapshot) => {
                if let Err(error) = store.apply(&snapshot) {
                    tracing::error!(code = error.code(), "refused the pulled key snapshot");
                }
            }
            Err(reason) => {
                metrics.record_key_registry_fetch_failure(reason);
                tracing::warn!(reason, "the key snapshot pull failed");
            }
        }
        if let Some(seconds) = store.stale_seconds() {
            #[allow(clippy::cast_precision_loss)]
            metrics.set_key_registry_stale_seconds(seconds as f64);
        }
        let interval = if store.cached_revision().is_some() {
            KEY_REFRESH_INTERVAL
        } else {
            FIRST_KEY_RETRY_INTERVAL
        };
        tokio::time::sleep(interval).await;
    }
}
