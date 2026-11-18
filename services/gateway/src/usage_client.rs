//! The gateway's client to Confidential Cloud's usage reporters' path.
//!
//! It posts the requests the gateway served to `POST <origin>/inference/usage`
//! (Confidential Cloud's docs/inference-billing.md, "Usage reporters"), with
//! the reporter key's certificate as its TLS client certificate
//! ([`crate::reporter`]). Confidential Cloud records each request once, by
//! its id, so a report may be sent again after any failure. The origin's host
//! is the TLS name the gateway checks against the image's public roots;
//! `tls_ca_pem` and `connect_address` are for tests against a local server.

use std::{net::IpAddr, time::Duration};

use futures_util::StreamExt;
use serde::Deserialize;

use crate::usage::Event;

/// The path Confidential Cloud takes usage reports at.
pub const USAGE_PATH: &str = "/inference/usage";
/// The most requests Confidential Cloud takes in one report.
pub const MAX_REPORT_REQUESTS: usize = 1_000;
const MAX_ANSWER_BYTES: usize = 1 << 20;

#[derive(Clone, Debug)]
pub struct Config {
    /// Confidential Cloud's usage origin, such as `https://usage.example.com`.
    pub origin: String,
    /// The reporter key's certificate and private key, in PEM.
    pub identity_pem: String,
    /// A CA to trust instead of the image's public roots.
    pub tls_ca_pem: Option<String>,
    /// Connect to this address instead of the address DNS returns. The TLS
    /// name is still the origin's host.
    pub connect_address: Option<IpAddr>,
}

/// One request Confidential Cloud refused for good, with its reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct Refusal {
    pub id: String,
    pub reason: String,
}

#[derive(Deserialize)]
struct Answer {
    #[serde(default)]
    refused: Vec<Refusal>,
}

/// Why a report was not recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendError {
    /// Confidential Cloud refused the report itself (400 or 413): sending it
    /// again cannot succeed.
    Rejected(u16),
    /// A failure that can pass later (reason code): no answer, a `5xx`, a
    /// `429`, or a `401`, which ends once an operator binds the key.
    Retry(&'static str),
}

pub struct UsageClient {
    http: reqwest::Client,
    usage_url: url::Url,
}

impl UsageClient {
    /// # Errors
    ///
    /// Returns an error for an origin that is not a plain `https` origin, an
    /// invalid identity or an invalid CA.
    pub fn new(config: &Config) -> Result<Self, String> {
        let origin = url::Url::parse(&config.origin).map_err(|_| "invalid usage origin")?;
        let host = origin
            .host_str()
            .ok_or("the usage origin has no host")?
            .to_owned();
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err("the usage origin must be a plain https origin".into());
        }
        let mut usage_url = origin.clone();
        usage_url.set_path(USAGE_PATH);
        let identity = reqwest::Identity::from_pem(config.identity_pem.as_bytes())
            .map_err(|_| "the reporter identity is invalid")?;
        let mut builder = reqwest::Client::builder()
            .identity(identity)
            .redirect(reqwest::redirect::Policy::none())
            // Straight to the pinned address: no proxy from the environment.
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30));
        if let Some(address) = config.connect_address {
            let port = origin.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(&host, std::net::SocketAddr::new(address, port));
        }
        if let Some(pem) = &config.tls_ca_pem {
            let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|_| "the usage CA is invalid")?;
            builder = builder.tls_certs_only([certificate]);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|_| "the usage client failed to build")?,
            usage_url,
        })
    }

    /// Report `events`, at most [`MAX_REPORT_REQUESTS`]. On success, every
    /// event is recorded but the refusals returned.
    ///
    /// # Errors
    ///
    /// See [`SendError`].
    pub async fn report(&self, events: &[Event]) -> Result<Vec<Refusal>, SendError> {
        let response = self
            .http
            .post(self.usage_url.clone())
            .json(&serde_json::json!({ "requests": events }))
            .send()
            .await
            .map_err(|_| SendError::Retry("unreachable"))?;
        let status = response.status();
        match status.as_u16() {
            200 => {}
            400 | 413 => return Err(SendError::Rejected(status.as_u16())),
            401 => return Err(SendError::Retry("unauthorized")),
            _ => return Err(SendError::Retry("http_status")),
        }
        let body = bounded_body(response, MAX_ANSWER_BYTES)
            .await
            .map_err(SendError::Retry)?;
        let answer: Answer =
            serde_json::from_slice(&body).map_err(|_| SendError::Retry("invalid_answer"))?;
        Ok(answer.refused)
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
