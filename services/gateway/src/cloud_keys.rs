//! The gateway's keys: Confidential Cloud answers whose each key is.
//!
//! Confidential Cloud keeps an org's inference keys and answers whose a key
//! is at `GET /inference/whoami`, with the key itself as the bearer token: a
//! live key is answered `200` with its record ID, and any other key `401`.
//! The gateway holds no copy of any key and no credential of its own.
//!
//! - Only a string of an inference key's form (`ci_` and 43 base64url
//!   characters) is sent, and only over TLS to the configured origin, with
//!   redirects off. Any other string is refused without a request.
//! - An answer is kept for a minute under the key's SHA-256, never the key,
//!   and never past the key's own expiry. So a revoked key stops working
//!   within a minute.
//! - When Confidential Cloud gives no answer, a key it answered live within
//!   the last ten minutes stays live, again never past its expiry. Any other
//!   key's request is answered `503`, not `401`: the key may be fine.
//! - A `429` is a refusal: Confidential Cloud limits only refused keys by
//!   address, so a live key is never answered `429`.
//! - A `402` is a live key of a prepaid org that is out of credits. It is
//!   kept like a refusal, so the key works again within a minute of a top-up,
//!   and never falls back to an earlier live answer.
//! - Live and refused answers are kept apart, so keys that are refused,
//!   however many, never push a live key out.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use futures_util::future::BoxFuture;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;

use crate::{ApiKeyVerifier, KeyCheck, metrics::GatewayMetrics};

/// The path Confidential Cloud answers whose a key is at.
pub const WHOAMI_PATH: &str = "/inference/whoami";
/// How long an answer is used without asking again.
pub const ANSWER_TTL: Duration = Duration::from_secs(60);
/// How long a live answer is used while Confidential Cloud gives none.
pub const STALE_TTL: Duration = Duration::from_secs(600);
/// The most live answers kept. A full cache drops the answers past the
/// stale time, and then all of them.
const MAX_LIVE: usize = 100_000;
/// The most refusals kept. A full cache drops them all.
const MAX_REFUSED: usize = 10_000;
/// The most checks in flight at once. A check waits for a free slot.
const MAX_IN_FLIGHT: usize = 64;
/// The largest whoami answer read.
const MAX_ANSWER_BYTES: usize = 4_096;
const KEY_PREFIX: &str = "ci_";
const KEY_BODY_LENGTH: usize = 43;

/// Where the checks go.
#[derive(Clone, Debug)]
pub struct Config {
    /// Confidential Cloud's API origin, such as `https://api.example.com`.
    pub origin: String,
    /// A CA to trust instead of the image's public roots, for tests against
    /// a local Confidential Cloud.
    pub tls_ca_pem: Option<String>,
    /// Connect to this address instead of the address DNS returns, for
    /// tests. The TLS name is still the origin's host.
    pub connect_address: Option<IpAddr>,
    /// [`ANSWER_TTL`] and [`STALE_TTL`], except in tests.
    pub answer_ttl: Duration,
    pub stale_ttl: Duration,
}

impl Config {
    #[must_use]
    pub fn new(origin: String) -> Self {
        Self {
            origin,
            tls_ca_pem: None,
            connect_address: None,
            answer_ttl: ANSWER_TTL,
            stale_ttl: STALE_TTL,
        }
    }
}

/// One live answer.
#[derive(Clone)]
struct Live {
    key_id: String,
    asked: Instant,
    expires_at: Option<SystemTime>,
}

impl Live {
    fn usable_for(&self, age: Duration) -> bool {
        self.asked.elapsed() < age && self.expires_at.is_none_or(|at| SystemTime::now() < at)
    }
}

enum Answer {
    Live(Live),
    Refused(Refusal),
}

/// Why a key is not served.
#[derive(Clone, Copy)]
enum Refusal {
    NotLive,
    OutOfCredits,
}

impl Refusal {
    fn check(self) -> KeyCheck {
        match self {
            Self::NotLive => KeyCheck::Refused,
            Self::OutOfCredits => KeyCheck::OutOfCredits,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Whoami {
    key_id: String,
    #[serde(default)]
    expires_at: Option<String>,
}

/// The keys, as Confidential Cloud answers them.
pub struct CloudKeys {
    http: reqwest::Client,
    whoami_url: url::Url,
    live: Mutex<HashMap<[u8; 32], Live>>,
    refused: Mutex<HashMap<[u8; 32], (Instant, Refusal)>>,
    slots: Semaphore,
    answer_ttl: Duration,
    stale_ttl: Duration,
    metrics: Arc<GatewayMetrics>,
}

impl CloudKeys {
    /// # Errors
    ///
    /// Returns an error for an origin that is not a plain `https` URL with a
    /// host and no path, or an invalid CA.
    pub fn new(config: &Config, metrics: Arc<GatewayMetrics>) -> Result<Self, String> {
        let origin =
            url::Url::parse(&config.origin).map_err(|_| "invalid Confidential Cloud origin")?;
        let host = origin
            .host_str()
            .ok_or("the Confidential Cloud origin has no host")?
            .to_owned();
        if origin.scheme() != "https"
            || !origin.username().is_empty()
            || origin.password().is_some()
            || !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err("the Confidential Cloud origin must be a plain https origin".into());
        }
        let mut whoami_url = origin.clone();
        whoami_url.set_path(WHOAMI_PATH);
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // Straight to the pinned address: no proxy from the environment.
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        if let Some(address) = config.connect_address {
            let port = origin.port_or_known_default().unwrap_or(443);
            builder = builder.resolve(&host, std::net::SocketAddr::new(address, port));
        }
        if let Some(pem) = &config.tls_ca_pem {
            let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|_| "the Confidential Cloud CA is invalid")?;
            builder = builder.tls_certs_only([certificate]);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|_| "the Confidential Cloud client failed to build")?,
            whoami_url,
            live: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            slots: Semaphore::new(MAX_IN_FLIGHT),
            answer_ttl: config.answer_ttl,
            stale_ttl: config.stale_ttl,
            metrics,
        })
    }

    async fn verify(&self, bearer: &str) -> KeyCheck {
        if !is_inference_key(bearer) {
            return KeyCheck::Refused;
        }
        let digest: [u8; 32] = Sha256::digest(bearer.as_bytes()).into();
        if let Some(key_id) = self.kept_live(&digest, self.answer_ttl) {
            self.metrics.record_cloud_key_check("kept");
            return KeyCheck::Live(key_id);
        }
        if let Some(refusal) = self.kept_refusal(&digest) {
            self.metrics.record_cloud_key_check("kept");
            return refusal.check();
        }
        let answer = match self.slots.acquire().await {
            Ok(_slot) => self.ask(bearer).await,
            Err(_) => None,
        };
        match answer {
            Some(Answer::Live(live)) => {
                self.metrics.record_cloud_key_check("live");
                let key_id = live.key_id.clone();
                self.keep_live(digest, live);
                KeyCheck::Live(key_id)
            }
            Some(Answer::Refused(refusal)) => {
                self.metrics.record_cloud_key_check(match refusal {
                    Refusal::NotLive => "refused",
                    Refusal::OutOfCredits => "out_of_credits",
                });
                self.keep_refusal(digest, refusal);
                refusal.check()
            }
            None => {
                if let Some(key_id) = self.kept_live(&digest, self.stale_ttl) {
                    self.metrics.record_cloud_key_check("stale");
                    KeyCheck::Live(key_id)
                } else {
                    self.metrics.record_cloud_key_check("unavailable");
                    KeyCheck::Unavailable
                }
            }
        }
    }

    /// Ask Confidential Cloud whose `bearer` is. `None` is no answer: a
    /// transport error, a status other than `200`, `401`, `402` or `429`, or a
    /// `200` that is not a whoami.
    async fn ask(&self, bearer: &str) -> Option<Answer> {
        let mut response = self
            .http
            .get(self.whoami_url.clone())
            .bearer_auth(bearer)
            .send()
            .await
            .ok()?;
        match response.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::TOO_MANY_REQUESTS => {
                return Some(Answer::Refused(Refusal::NotLive));
            }
            reqwest::StatusCode::PAYMENT_REQUIRED => {
                return Some(Answer::Refused(Refusal::OutOfCredits));
            }
            _ => return None,
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len() + chunk.len() > MAX_ANSWER_BYTES {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        let whoami: Whoami = serde_json::from_slice(&body).ok()?;
        if whoami.key_id.is_empty() {
            return None;
        }
        let expires_at = match whoami.expires_at {
            Some(at) => Some(SystemTime::from(
                time::OffsetDateTime::parse(&at, &time::format_description::well_known::Rfc3339)
                    .ok()?,
            )),
            None => None,
        };
        Some(Answer::Live(Live {
            key_id: whoami.key_id,
            asked: Instant::now(),
            expires_at,
        }))
    }

    fn kept_live(&self, digest: &[u8; 32], age: Duration) -> Option<String> {
        let live = self.live.lock().ok()?;
        live.get(digest)
            .filter(|answer| answer.usable_for(age))
            .map(|answer| answer.key_id.clone())
    }

    fn kept_refusal(&self, digest: &[u8; 32]) -> Option<Refusal> {
        self.refused
            .lock()
            .ok()
            .and_then(|refused| refused.get(digest).copied())
            .filter(|(at, _)| at.elapsed() < self.answer_ttl)
            .map(|(_, refusal)| refusal)
    }

    fn keep_live(&self, digest: [u8; 32], answer: Live) {
        if let Ok(mut refused) = self.refused.lock() {
            refused.remove(&digest);
        }
        let Ok(mut live) = self.live.lock() else {
            return;
        };
        if live.len() >= MAX_LIVE {
            live.retain(|_, answer| answer.usable_for(self.stale_ttl));
            if live.len() >= MAX_LIVE {
                live.clear();
            }
        }
        live.insert(digest, answer);
    }

    fn keep_refusal(&self, digest: [u8; 32], refusal: Refusal) {
        if let Ok(mut live) = self.live.lock() {
            live.remove(&digest);
        }
        let Ok(mut refused) = self.refused.lock() else {
            return;
        };
        if refused.len() >= MAX_REFUSED {
            refused.clear();
        }
        refused.insert(digest, (Instant::now(), refusal));
    }
}

impl ApiKeyVerifier for CloudKeys {
    fn check<'a>(&'a self, bearer: &'a str) -> BoxFuture<'a, KeyCheck> {
        Box::pin(self.verify(bearer))
    }
}

fn is_inference_key(bearer: &str) -> bool {
    bearer.strip_prefix(KEY_PREFIX).is_some_and(|body| {
        body.len() == KEY_BODY_LENGTH
            && body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    })
}

#[cfg(test)]
mod tests {
    use super::is_inference_key;

    #[test]
    fn only_an_inference_key_is_sent() {
        let body = "A".repeat(43);
        assert!(is_inference_key(&format!("ci_{body}")));
        assert!(is_inference_key(
            "ci_abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"
        ));
        assert!(!is_inference_key(&format!("ci_{body}A")));
        assert!(!is_inference_key(&format!("ci_{}", "A".repeat(42))));
        assert!(!is_inference_key(&format!("sk_{body}")));
        assert!(!is_inference_key(&format!("ci_{}=", "A".repeat(42))));
        assert!(!is_inference_key(&format!("ci_{}.", "A".repeat(42))));
    }
}
