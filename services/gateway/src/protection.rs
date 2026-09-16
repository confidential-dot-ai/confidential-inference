//! Bounded public request controls.

use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Response, StatusCode, header},
    middleware::Next,
    response::IntoResponse,
};
use ipnet::IpNet;
use serde_json::json;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const ADDRESS_CAPACITY: usize = 4_096;

#[derive(Clone, Debug)]
pub struct ProtectionConfig {
    pub maximum_headers: usize,
    pub maximum_header_bytes: usize,
    pub maximum_uri_bytes: usize,
    pub body_timeout: Duration,
    pub stream_idle_timeout: Duration,
    pub global_request_concurrency: usize,
    pub per_address_concurrency: usize,
    pub inference_concurrency: usize,
    pub inference_queue: usize,
    pub queue_timeout: Duration,
    pub per_key_concurrency: usize,
    pub attestation_concurrency: usize,
    pub requests_per_address_per_second: u32,
    pub trusted_proxy_cidrs: Vec<IpNet>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            maximum_headers: 64,
            maximum_header_bytes: 16 * 1_024,
            maximum_uri_bytes: 2 * 1_024,
            body_timeout: Duration::from_secs(10),
            stream_idle_timeout: Duration::from_secs(60),
            global_request_concurrency: 256,
            per_address_concurrency: 16,
            inference_concurrency: 64,
            inference_queue: 64,
            queue_timeout: Duration::from_secs(2),
            per_key_concurrency: 4,
            attestation_concurrency: 4,
            requests_per_address_per_second: 30,
            trusted_proxy_cidrs: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ProtectionState {
    pub config: ProtectionConfig,
    inference_slots: Arc<Semaphore>,
    inference_admission: Arc<Semaphore>,
    attestation_slots: Arc<Semaphore>,
    public_requests: Arc<Semaphore>,
    address_slots: Arc<Mutex<BTreeMap<IpAddr, Arc<Semaphore>>>>,
    key_slots: Arc<Mutex<BTreeMap<String, Arc<Semaphore>>>>,
    addresses: Arc<Mutex<BTreeMap<IpAddr, AddressWindow>>>,
}

#[derive(Clone, Copy)]
struct AddressWindow {
    started: Instant,
    requests: u32,
}

pub struct InferencePermits {
    _key: OwnedSemaphorePermit,
    _admission: OwnedSemaphorePermit,
    _execution: OwnedSemaphorePermit,
}

#[derive(Debug)]
pub struct CapacityError;

impl ProtectionState {
    #[must_use]
    pub fn new(config: ProtectionConfig) -> Self {
        Self {
            inference_slots: Arc::new(Semaphore::new(config.inference_concurrency)),
            inference_admission: Arc::new(Semaphore::new(
                config
                    .inference_concurrency
                    .saturating_add(config.inference_queue),
            )),
            attestation_slots: Arc::new(Semaphore::new(config.attestation_concurrency)),
            public_requests: Arc::new(Semaphore::new(config.global_request_concurrency)),
            address_slots: Arc::new(Mutex::new(BTreeMap::new())),
            key_slots: Arc::new(Mutex::new(BTreeMap::new())),
            addresses: Arc::new(Mutex::new(BTreeMap::new())),
            config,
        }
    }

    /// Reserve one key slot, one bounded queue slot, and one execution slot.
    ///
    /// # Errors
    ///
    /// Returns an error when any capacity limit rejects the request.
    pub async fn inference_permits(&self, key_id: &str) -> Result<InferencePermits, CapacityError> {
        let key_slots = {
            let mut slots = self.key_slots.lock().map_err(|_| CapacityError)?;
            slots
                .entry(key_id.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(self.config.per_key_concurrency)))
                .clone()
        };
        let key = key_slots.try_acquire_owned().map_err(|_| CapacityError)?;
        let admission = self
            .inference_admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| CapacityError)?;
        let execution = tokio::time::timeout(
            self.config.queue_timeout,
            self.inference_slots.clone().acquire_owned(),
        )
        .await
        .map_err(|_| CapacityError)?
        .map_err(|_| CapacityError)?;
        Ok(InferencePermits {
            _key: key,
            _admission: admission,
            _execution: execution,
        })
    }

    /// Reserve one attestation slot without waiting.
    ///
    /// # Errors
    ///
    /// Returns an error when all attestation slots are in use.
    pub fn attestation_permit(&self) -> Result<OwnedSemaphorePermit, CapacityError> {
        self.attestation_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CapacityError)
    }

    fn accept_address(&self, address: IpAddr) -> bool {
        let now = Instant::now();
        let Ok(mut addresses) = self.addresses.lock() else {
            return false;
        };
        addresses.retain(|_, window| now.duration_since(window.started) < Duration::from_secs(2));
        if !addresses.contains_key(&address) && addresses.len() >= ADDRESS_CAPACITY {
            return false;
        }
        let window = addresses.entry(address).or_insert(AddressWindow {
            started: now,
            requests: 0,
        });
        if now.duration_since(window.started) >= Duration::from_secs(1) {
            *window = AddressWindow {
                started: now,
                requests: 0,
            };
        }
        if window.requests >= self.config.requests_per_address_per_second {
            return false;
        }
        window.requests += 1;
        true
    }
}

pub async fn enforce_public_limits(
    State(state): State<Arc<ProtectionState>>,
    request: Request,
    next: Next,
) -> Response<Body> {
    let header_bytes = request
        .headers()
        .iter()
        .fold(0usize, |total, (name, value)| {
            total
                .saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
        });
    if request.headers().len() > state.config.maximum_headers
        || header_bytes > state.config.maximum_header_bytes
    {
        return error(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "request_headers_too_large",
            None,
        );
    }
    if request.uri().to_string().len() > state.config.maximum_uri_bytes {
        return error(StatusCode::URI_TOO_LONG, "request_uri_too_long", None);
    }
    let Ok(client) = client_address(request.headers(), request.extensions().get(), &state.config)
    else {
        return error(StatusCode::BAD_REQUEST, "invalid_forwarding_headers", None);
    };
    let Ok(_global_permit) = state.public_requests.clone().try_acquire_owned() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "request_capacity",
            Some("1"),
        );
    };
    let address_slots = {
        let Ok(mut slots) = state.address_slots.lock() else {
            return error(
                StatusCode::SERVICE_UNAVAILABLE,
                "request_capacity",
                Some("1"),
            );
        };
        if !slots.contains_key(&client) && slots.len() >= ADDRESS_CAPACITY {
            return error(StatusCode::TOO_MANY_REQUESTS, "address_capacity", Some("1"));
        }
        slots
            .entry(client)
            .or_insert_with(|| Arc::new(Semaphore::new(state.config.per_address_concurrency)))
            .clone()
    };
    let Ok(_address_permit) = address_slots.try_acquire_owned() else {
        return error(StatusCode::TOO_MANY_REQUESTS, "address_capacity", Some("1"));
    };
    if !state.accept_address(client) {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "address_rate_limited",
            Some("1"),
        );
    }
    next.run(request).await
}

fn client_address(
    headers: &HeaderMap,
    connection: Option<&ConnectInfo<SocketAddr>>,
    config: &ProtectionConfig,
) -> Result<IpAddr, ()> {
    let forwarded = headers.get("x-forwarded-for");
    if headers.contains_key("forwarded") {
        return Err(());
    }
    let peer = connection.map(|value| value.0.ip());
    let Some(value) = forwarded else {
        return Ok(peer.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)));
    };
    let peer = peer.ok_or(())?;
    if !config
        .trusted_proxy_cidrs
        .iter()
        .any(|cidr| cidr.contains(&peer))
    {
        return Err(());
    }
    let text = value.to_str().map_err(|_| ())?;
    if text.contains(',') || text.trim() != text {
        return Err(());
    }
    let address: IpAddr = text.parse().map_err(|_| ())?;
    if let Some(real_ip) = headers.get("x-real-ip") {
        let real_ip = real_ip.to_str().map_err(|_| ())?;
        if real_ip.trim() != real_ip
            || real_ip.contains(',')
            || real_ip.parse::<IpAddr>().map_err(|_| ())? != address
        {
            return Err(());
        }
    }
    Ok(address)
}

#[must_use]
pub fn overload(code: &'static str) -> Response<Body> {
    error(StatusCode::TOO_MANY_REQUESTS, code, Some("1"))
}

fn error(
    status: StatusCode,
    code: &'static str,
    retry_after: Option<&'static str>,
) -> Response<Body> {
    let mut response = (
        status,
        axum::Json(json!({"error":{"code":code,"message":status.canonical_reason().unwrap_or("Request failed.")}})),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(value) = retry_after {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static(value));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use tower::ServiceExt as _;

    fn request(uri: &str, peer: IpAddr) -> Request {
        let mut request = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap_or_else(|_| unreachable!());
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(peer, 1234)));
        request
    }

    #[tokio::test]
    async fn rejects_spoofed_forwarding_headers() {
        let state = Arc::new(ProtectionState::new(ProtectionConfig::default()));
        let app = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state, enforce_public_limits),
        );
        let mut request = request("/", "192.0.2.1".parse().unwrap_or_else(|_| unreachable!()));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
        request
            .headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("198.51.100.2"));
        assert_eq!(
            app.oneshot(request)
                .await
                .unwrap_or_else(|_| unreachable!())
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn trusts_one_address_from_a_configured_proxy() {
        let config = ProtectionConfig {
            trusted_proxy_cidrs: vec!["192.0.2.0/24".parse().unwrap_or_else(|_| unreachable!())],
            ..ProtectionConfig::default()
        };
        let state = Arc::new(ProtectionState::new(config));
        let app = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state, enforce_public_limits),
        );
        let mut request = request("/", "192.0.2.1".parse().unwrap_or_else(|_| unreachable!()));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
        request
            .headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("198.51.100.2"));
        assert_eq!(
            app.oneshot(request)
                .await
                .unwrap_or_else(|_| unreachable!())
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn rejects_disagreeing_tls_lb_addresses() {
        let config = ProtectionConfig {
            trusted_proxy_cidrs: vec!["192.0.2.0/24".parse().unwrap_or_else(|_| unreachable!())],
            ..ProtectionConfig::default()
        };
        let state = Arc::new(ProtectionState::new(config));
        let app = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state, enforce_public_limits),
        );
        let mut request = request("/", "192.0.2.1".parse().unwrap_or_else(|_| unreachable!()));
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.2"));
        request
            .headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("198.51.100.3"));
        assert_eq!(
            app.oneshot(request)
                .await
                .unwrap_or_else(|_| unreachable!())
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}
