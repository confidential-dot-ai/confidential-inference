use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayAvailability, GatewayConfig,
    UnavailableAttestation, metrics::GatewayMetrics, router,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tower::ServiceExt;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn runtime_models_change_without_interrupting_an_active_request()
-> Result<(), Box<dyn std::error::Error>> {
    use confidential_gateway::{
        router_with_runtime, runtime_config::MountedConfig, runtime_settings::GatewaySettings,
    };
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("settings.json");
    let settings = |revision, name: &str| GatewaySettings {
        schema_version: 1,
        revision,
        router_service: None,
        evidence: None,
        catalog_model_ids: vec![name.into()],
        inference_model_ids: vec![name.into()],
        maximum_body_bytes: 1024,
        upstream_timeout_seconds: 30,
        body_timeout_seconds: 10,
        stream_idle_timeout_seconds: 20,
        attestation_cache_seconds: 10,
        global_request_concurrency: 256,
        per_address_concurrency: 16,
        inference_concurrency: 1,
        inference_queue: 0,
        queue_timeout_seconds: 2,
        per_key_concurrency: 4,
        attestation_concurrency: 4,
        requests_per_address_per_second: 30,
    };
    std::fs::write(&path, serde_json::to_vec(&settings(1, "old"))?)?;
    let runtime = Arc::new(MountedConfig::open(
        path.clone(),
        4096,
        GatewaySettings::validate,
    )?);
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let upstream = Router::new().route("/v1/chat/completions", post({
        let entered = entered.clone(); let release = release.clone();
        move |Json(value): Json<Value>| {
            let entered = entered.clone(); let release = release.clone();
            async move {
                entered.notify_one();
                release.notified().await;
                Json(json!({"model": value["model"], "choices":[{"message":{"content":"complete"},"finish_reason":"stop"}]}))
            }
        }
    }));
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await });
    let app = router_with_runtime(
        GatewayConfig {
            catalog_model_ids: vec!["startup".into()],
            inference_model_ids: vec!["startup".into()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 1024,
            upstream_timeout: Duration::from_secs(30),
            protection: confidential_gateway::protection::ProtectionConfig {
                inference_concurrency: 1,
                inference_queue: 0,
                ..Default::default()
            },
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        GatewayAvailability::default(),
        Arc::new(UnavailableAttestation),
        reqwest::Client::new(),
        Some(runtime.clone()),
        None,
    );
    let completion = |model: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer accepted")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({"model":model}).to_string()))
    };
    let active = tokio::spawn(app.clone().oneshot(completion("old")?));
    tokio::time::timeout(Duration::from_secs(3), entered.notified()).await?;
    std::fs::write(&path, serde_json::to_vec(&settings(2, "new"))?)?;
    runtime.refresh(GatewaySettings::validate);
    let catalog = app
        .clone()
        .oneshot(Request::builder().uri("/v1/models").body(Body::empty())?)
        .await?;
    let catalog: Value =
        serde_json::from_slice(&axum::body::to_bytes(catalog.into_body(), 4096).await?)?;
    assert_eq!(catalog["data"][0]["id"], "new");
    assert_eq!(
        app.clone().oneshot(completion("old")?).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    // A reload must not reset the execution/admission counters.
    assert_eq!(
        app.clone().oneshot(completion("new")?).await?.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(3), active).await???;
    assert_eq!(response.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(response["model"], "old");
    assert_eq!(response["choices"][0]["message"]["content"], "complete");
    server.abort();
    Ok(())
}

struct Keys;

#[cfg(target_os = "linux")]
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn router_file_change_moves_new_requests_and_tracks_the_old_request()
-> Result<(), Box<dyn std::error::Error>> {
    use confidential_gateway::{
        metrics::MetricsSource as _, router_with_runtime, runtime_config::MountedConfig,
        runtime_settings::GatewaySettings,
    };
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("settings.json");
    let settings = |revision, router| {
        json!({"schemaVersion":1,"revision":revision,"routerService":router,
        "catalogModelIds":["public"],"inferenceModelIds":["public"],"maximumBodyBytes":1024,
        "upstreamTimeoutSeconds":30,"bodyTimeoutSeconds":10,"streamIdleTimeoutSeconds":20,
        "attestationCacheSeconds":10,"globalRequestConcurrency":256,"perAddressConcurrency":16,
        "inferenceConcurrency":4,"inferenceQueue":0,"queueTimeoutSeconds":2,
        "perKeyConcurrency":4,"attestationConcurrency":4,"requestsPerAddressPerSecond":30})
    };
    std::fs::write(&path, settings(1, "router-one").to_string())?;
    let runtime = Arc::new(MountedConfig::<GatewaySettings>::open(
        path.clone(),
        4096,
        GatewaySettings::validate,
    )?);
    let random = uuid::Uuid::new_v4();
    let bytes = random.as_bytes();
    let old_ip = std::net::Ipv4Addr::new(127, bytes[0].max(1), bytes[1], 1);
    let new_ip = std::net::Ipv4Addr::new(127, bytes[0].max(1), bytes[1], 2);
    let old_listener = tokio::net::TcpListener::bind((old_ip, 30000)).await?;
    let new_listener = tokio::net::TcpListener::bind((new_ip, 30000)).await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let old_requests = Arc::new(AtomicUsize::new(0));
    let old_router = Router::new().route("/v1/chat/completions", post({
        let entered = entered.clone(); let release = release.clone(); let requests = old_requests.clone();
        move || { let entered = entered.clone(); let release = release.clone(); let requests = requests.clone();
            async move { requests.fetch_add(1, Ordering::SeqCst); entered.notify_one(); release.notified().await;
                Json(json!({"model":"public","choices":[{"message":{"content":"old"},"finish_reason":"stop"}]})) }
        }
    }));
    let new_router = Router::new().route("/v1/chat/completions", post(|| async {
        Json(json!({"model":"public","choices":[{"message":{"content":"new"},"finish_reason":"stop"}]}))
    }));
    let old_server = tokio::spawn(async move { axum::serve(old_listener, old_router).await });
    let new_server = tokio::spawn(async move { axum::serve(new_listener, new_router).await });
    let namespace = format!("test-{}", &random.to_string()[..8]);
    let old_host = format!("router-one.{namespace}.svc.cluster.local");
    let new_host = format!("router-two.{namespace}.svc.cluster.local");
    let client = reqwest::Client::builder()
        .no_proxy()
        .resolve(&old_host, SocketAddr::from((old_ip, 30000)))
        .resolve(&new_host, SocketAddr::from((new_ip, 30000)))
        .build()?;
    let metrics = Arc::new(GatewayMetrics::new("test"));
    let app = router_with_runtime(
        GatewayConfig {
            catalog_model_ids: vec!["public".into()],
            inference_model_ids: vec!["public".into()],
            upstream_base_url: format!("http://{old_host}:30000"),
            maximum_body_bytes: 1024,
            upstream_timeout: Duration::from_secs(30),
            protection: confidential_gateway::protection::ProtectionConfig::default(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        metrics.clone(),
        GatewayAvailability::default(),
        Arc::new(UnavailableAttestation),
        client,
        Some(runtime.clone()),
        Some(namespace),
    );
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/chat/completions")
            .header(header::AUTHORIZATION, "Bearer accepted")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"model":"public"}"#))
    };
    let old = tokio::spawn(app.clone().oneshot(request()?));
    tokio::time::timeout(Duration::from_secs(3), entered.notified()).await?;
    std::fs::write(&path, settings(2, "router-two").to_string())?;
    runtime.refresh(GatewaySettings::validate);
    let new = app.oneshot(request()?).await?;
    assert_eq!(new.status(), StatusCode::OK);
    let new: Value = serde_json::from_slice(&axum::body::to_bytes(new.into_body(), 4096).await?)?;
    assert_eq!(new["choices"][0]["message"]["content"], "new");
    assert_eq!(old_requests.load(Ordering::SeqCst), 1);
    let labels = format!("env=\"test\",router=\"{old_host}\"");
    assert!(
        metrics
            .render_prometheus()
            .contains(&format!("gateway_router_requests_active{{{labels}}} 1"))
    );
    release.notify_one();
    let old = tokio::time::timeout(Duration::from_secs(3), old).await???;
    assert_eq!(runtime.status().retired_snapshot_readers.get(&1), Some(&1));
    let old: Value = serde_json::from_slice(&axum::body::to_bytes(old.into_body(), 4096).await?)?;
    assert_eq!(old["choices"][0]["message"]["content"], "old");
    assert!(runtime.status().retired_snapshot_readers.is_empty());
    assert!(
        metrics
            .render_prometheus()
            .contains(&format!("gateway_router_requests_active{{{labels}}} 0"))
    );
    old_server.abort();
    new_server.abort();
    Ok(())
}

impl ApiKeyVerifier for Keys {
    fn verify_bearer(&self, value: &str) -> Option<String> {
        (value == "accepted").then(|| "key_record_1".to_owned())
    }
}

struct Audit;

impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

async fn spawn_upstream() -> (SocketAddr, oneshot::Sender<()>) {
    async fn completion(Json(value): Json<Value>) -> Json<Value> {
        Json(json!({
            "id": "response-1",
            "object": "chat.completion",
            "model": value["model"],
            "choices": [{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]
        }))
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(completion))
                .into_make_service(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, stop_tx)
}

async fn spawn_unavailable_upstream() -> (SocketAddr, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route(
                "/v1/chat/completions",
                post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
            ),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, stop_tx)
}

async fn spawn_redirect_upstream(
    status: StatusCode,
    location: String,
) -> (SocketAddr, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route(
                "/v1/chat/completions",
                post(move || {
                    let location = location.clone();
                    async move { (status, [(header::LOCATION, location)]) }
                }),
            ),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, stop_tx)
}

async fn spawn_capture() -> (SocketAddr, Arc<AtomicUsize>, oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let body_length = Arc::new(AtomicUsize::new(0));
    let observed_body_length = Arc::clone(&body_length);
    let (stop_tx, stop_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            Router::new().route(
                "/capture",
                post(move |body: Bytes| {
                    let observed_body_length = Arc::clone(&observed_body_length);
                    async move {
                        observed_body_length.store(body.len(), Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    }
                }),
            ),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await;
    });
    (address, body_length, stop_tx)
}

fn no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_| unreachable!())
}

fn app_with_client(address: SocketAddr, client: reqwest::Client) -> Router {
    router(
        GatewayConfig {
            catalog_model_ids: vec!["deepseek".to_owned()],
            inference_model_ids: vec!["deepseek".to_owned()],
            upstream_base_url: format!("http://{address}"),
            maximum_body_bytes: 1_024 * 1_024,
            upstream_timeout: Duration::from_secs(5),
            protection: confidential_gateway::protection::ProtectionConfig::default(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        Arc::new(GatewayMetrics::new("test")),
        GatewayAvailability::default(),
        Arc::new(UnavailableAttestation),
        client,
    )
}

fn app(address: SocketAddr) -> Router {
    app_with_client(address, no_redirect_client())
}

#[tokio::test]
async fn gateway_forwards_to_the_internal_router_without_the_caller_key() {
    let (address, stop) = spawn_upstream().await;
    let response = app(address)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"model":"deepseek","messages":[{"role":"user","content":"hello"}]})
                        .to_string(),
                ))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), 200);
    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_does_not_authorize_an_unknown_model_for_forwarding() {
    let (address, stop) = spawn_upstream().await;
    let response = app(address)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(json!({"model":"unknown"}).to_string()))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), 401);
    let body = axum::body::to_bytes(response.into_body(), 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default()["error"]["code"],
        "model_not_authorized"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_normalizes_an_unavailable_inference_router() {
    let (address, stop) = spawn_unavailable_upstream().await;
    let response = app(address)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("authorization", "Bearer accepted")
                .header("content-type", "application/json")
                .body(Body::from(json!({"model":"deepseek"}).to_string()))
                .unwrap_or_else(|_| unreachable!()),
        )
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()[header::RETRY_AFTER], "30");
    let body = axum::body::to_bytes(response.into_body(), 1_024)
        .await
        .unwrap_or_else(|_| unreachable!());
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap_or_default()["error"]["code"],
        "inference_unavailable"
    );
    let _ = stop.send(());
}

#[tokio::test]
async fn gateway_does_not_forward_request_bodies_on_upstream_redirects() {
    for status in [
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::PERMANENT_REDIRECT,
    ] {
        let (capture_address, capture_body_length, capture_stop) = spawn_capture().await;
        let location = format!("http://{capture_address}/capture");
        let (redirect_address, redirect_stop) = spawn_redirect_upstream(status, location).await;
        let response = app(redirect_address)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/chat/completions")
                    .header("authorization", "Bearer accepted")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "model":"deepseek",
                            "messages":[{"role":"user","content":"secret prompt"}]
                        })
                        .to_string(),
                    ))
                    .unwrap_or_else(|_| unreachable!()),
            )
            .await
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(response.status(), status);
        assert!(
            capture_body_length.load(Ordering::SeqCst) == 0,
            "the redirect forwarded the request body"
        );
        let _ = redirect_stop.send(());
        let _ = capture_stop.send(());
    }
}

#[tokio::test]
async fn gateway_preserves_public_model_for_both_completion_routes_and_streams() {
    async fn backend(Json(request): Json<Value>) -> axum::response::Response {
        use axum::response::IntoResponse;
        assert_eq!(request["model"], "deepseek");
        let result = json!({"id":"same", "model":"internal-version", "choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":2}});
        if request["stream"] == true {
            let event = format!("data: {result}\n\ndata: [DONE]\n\n");
            let chunks: Vec<_> = event
                .as_bytes()
                .chunks(3)
                .map(|chunk| Ok::<_, std::io::Error>(Bytes::copy_from_slice(chunk)))
                .collect();
            (
                [(header::CONTENT_TYPE, "text/event-stream")],
                Body::from_stream(futures_util::stream::iter(chunks)),
            )
                .into_response()
        } else {
            Json(result).into_response()
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|_| unreachable!());
    let address = listener.local_addr().unwrap_or_else(|_| unreachable!());
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new()
                .route("/v1/chat/completions", post(backend))
                .route("/v1/completions", post(backend)),
        )
        .await
    });
    for route in ["/v1/chat/completions", "/v1/completions"] {
        for stream in [false, true] {
            let response = app(address)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(route)
                        .header("authorization", "Bearer accepted")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            json!({"model":"deepseek","stream":stream}).to_string(),
                        ))
                        .unwrap_or_else(|_| unreachable!()),
                )
                .await
                .unwrap_or_else(|_| unreachable!());
            assert_eq!(response.status(), 200);
            let bytes = axum::body::to_bytes(response.into_body(), 8192)
                .await
                .unwrap_or_else(|_| unreachable!());
            let text = std::str::from_utf8(&bytes).unwrap_or_else(|_| unreachable!());
            assert!(!text.contains("internal-version"));
            let json_bytes = if stream {
                text.lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .unwrap_or_else(|| unreachable!())
                    .as_bytes()
            } else {
                &bytes
            };
            let value: Value =
                serde_json::from_slice(json_bytes).unwrap_or_else(|_| unreachable!());
            assert_eq!(value["model"], "deepseek");
            assert_eq!(value["choices"][0]["message"]["content"], "ok");
            assert_eq!(value["usage"]["prompt_tokens"], 11);
            if stream {
                assert!(text.ends_with("data: [DONE]\n\n"));
            }
        }
    }
    server.abort();
}
