use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AttestationError, AttestationProvider, AuditEvent, AuditSink,
    GatewayAvailability, GatewayConfig,
    metrics::GatewayMetrics,
    protection::{ProtectionConfig, ProtectionState},
    router,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

struct Keys;

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, bearer: &str) -> Option<String> {
        match bearer {
            "valid-a" => Some("key-a".to_owned()),
            "valid-b" => Some("key-b".to_owned()),
            _ => None,
        }
    }
}

struct Audit;

impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

struct SlowAttestation;

#[async_trait::async_trait]
impl AttestationProvider for SlowAttestation {
    async fn response(&self, nonce: &[u8; 32]) -> Result<Value, AttestationError> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(json!({"nonce": nonce}))
    }
}

async fn start_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/v1/chat/completions",
                post(|| async { Json(json!({"id":"ok"})) }),
            ),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    });
    format!("http://{address}")
}

fn request(path: String, key: Option<&str>) -> Request<Body> {
    let method = if path.starts_with("/v1/") && !path.starts_with("/v1/attestation") {
        "POST"
    } else {
        "GET"
    };
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(key) = key {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    builder
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"model":"deepseek"}"#))
        .unwrap_or_else(|_| unreachable!())
}

#[tokio::test]
async fn invalid_key_and_attestation_floods_do_not_consume_inference_slots() {
    let protection = ProtectionConfig {
        inference_concurrency: 2,
        inference_queue: 1,
        per_key_concurrency: 1,
        attestation_concurrency: 1,
        requests_per_address_per_second: 10_000,
        global_request_concurrency: 512,
        per_address_concurrency: 512,
        ..ProtectionConfig::default()
    };
    let app = router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: start_upstream().await,
            maximum_body_bytes: 1_024,
            upstream_timeout: Duration::from_secs(2),
            protection,
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        GatewayAvailability::default(),
        Arc::new(SlowAttestation),
        reqwest::Client::new(),
    );

    let mut flood = Vec::new();
    for _ in 0..256 {
        let service = app.clone();
        flood.push(tokio::spawn(async move {
            service
                .oneshot(request("/v1/chat/completions".to_owned(), Some("invalid")))
                .await
                .unwrap_or_else(|_| unreachable!())
                .status()
        }));
    }
    for value in 0..32_u8 {
        let service = app.clone();
        let nonce = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [value; 32],
        );
        flood.push(tokio::spawn(async move {
            service
                .oneshot(request(format!("/attestation?nonce={nonce}"), None))
                .await
                .unwrap_or_else(|_| unreachable!())
                .status()
        }));
    }

    let valid = app
        .oneshot(request("/v1/chat/completions".to_owned(), Some("valid-a")))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(valid.status(), StatusCode::OK);
    assert!(to_bytes(valid.into_body(), 1_024).await.is_ok());

    let statuses = futures_util::future::join_all(flood).await;
    assert!(statuses.iter().take(256).all(|status| {
        status
            .as_ref()
            .is_ok_and(|value| *value == StatusCode::UNAUTHORIZED)
    }));
    assert!(statuses.iter().skip(256).any(|status| {
        status
            .as_ref()
            .is_ok_and(|value| *value == StatusCode::TOO_MANY_REQUESTS)
    }));
}

#[tokio::test]
async fn key_and_queue_capacity_fail_with_a_bounded_retry() {
    let config = ProtectionConfig {
        inference_concurrency: 1,
        inference_queue: 0,
        per_key_concurrency: 1,
        ..ProtectionConfig::default()
    };
    let state = ProtectionState::new(config);
    let first = state.inference_permits("key-a").await;
    assert!(first.is_ok());
    assert!(state.inference_permits("key-a").await.is_err());
    assert!(state.inference_permits("key-b").await.is_err());
}

struct HeldMetadata {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl AttestationProvider for HeldMetadata {
    fn requires_nonce(&self) -> bool {
        false
    }

    async fn response(&self, _: &[u8; 32]) -> Result<Value, AttestationError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(json!({"schemaVersion": 3}))
    }
}

async fn metadata_app(config: ProtectionConfig, provider: Arc<HeldMetadata>) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: start_upstream().await,
            maximum_body_bytes: 1_024,
            upstream_timeout: Duration::from_secs(2),
            protection: config,
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        GatewayAvailability::default(),
        provider,
        reqwest::Client::new(),
    )
}

#[tokio::test]
async fn public_metadata_overload_keeps_inference_available_and_releases_the_slot() {
    let provider = Arc::new(HeldMetadata {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let app = metadata_app(
        ProtectionConfig {
            attestation_concurrency: 1,
            requests_per_address_per_second: 10_000,
            ..ProtectionConfig::default()
        },
        provider.clone(),
    )
    .await;
    let service = app.clone();
    let active = tokio::spawn(async move {
        service
            .oneshot(request("/attestation".to_owned(), None))
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), provider.entered.notified())
        .await
        .unwrap_or_else(|_| panic!("metadata request did not enter its provider"));
    let rejected = app
        .clone()
        .oneshot(request("/v1/attestation".to_owned(), None))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
    let valid = app
        .clone()
        .oneshot(request("/v1/chat/completions".to_owned(), Some("valid-a")))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(valid.status(), StatusCode::OK);
    provider.release.notify_one();
    assert_eq!(
        active
            .await
            .unwrap_or_else(|_| unreachable!())
            .unwrap_or_else(|_| unreachable!())
            .status(),
        StatusCode::OK
    );
    provider.release.notify_one();
    let next = app
        .oneshot(request("/attestation".to_owned(), None))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(next.status(), StatusCode::OK);
}

#[tokio::test]
async fn public_metadata_without_key_or_nonce_uses_the_address_rate_limit() {
    let provider = Arc::new(HeldMetadata {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let app = metadata_app(
        ProtectionConfig {
            requests_per_address_per_second: 1,
            ..ProtectionConfig::default()
        },
        provider.clone(),
    )
    .await;
    provider.release.notify_one();
    let first = app
        .clone()
        .oneshot(request("/attestation".to_owned(), None))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(first.status(), StatusCode::OK);
    let second = app
        .oneshot(request("/attestation".to_owned(), None))
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers()[header::RETRY_AFTER], "1");
    let bytes = to_bytes(second.into_body(), 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    assert!(String::from_utf8_lossy(&bytes).contains("address_rate_limited"));
}
