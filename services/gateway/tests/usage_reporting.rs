//! Usage reported to a local HTTPS Confidential Cloud that, like the real
//! one, takes any TLS client certificate and records usage only from a bound
//! key: the reporter certificate, the events, refusals, a split report, an
//! unbound key and a full spool.
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::State,
    http::{Request, StatusCode, header},
    response::IntoResponse,
    routing::post,
};
use confidential_gateway::{
    ApiKeyVerifier, AuditEvent, AuditSink, GatewayConfig, KeyCheck,
    metrics::{GatewayMetrics, MetricsSource},
    protection::ProtectionConfig,
    reporter::ReporterKey,
    reporter_key_router, router_with_usage,
    usage::{MAX_PENDING_EVENTS, Model, Outcome, Recorder},
    usage_client::{self, USAGE_PATH, UsageClient},
};
use futures_util::future::BoxFuture;
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
    client::danger::HandshakeSignatureValid,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use serde_json::{Value, json};
use tower::ServiceExt;

const SECRET: [u8; 32] = [7; 32];

struct Audit;
impl AuditSink for Audit {
    fn record(&self, _: AuditEvent) {}
}

/// Every bearer is a live key of record `ik-test`, except `broke`, whose
/// org is out of credits.
struct Keys;
impl ApiKeyVerifier for Keys {
    fn check<'a>(&'a self, bearer: &'a str) -> BoxFuture<'a, KeyCheck> {
        Box::pin(std::future::ready(if bearer == "broke" {
            KeyCheck::OutOfCredits
        } else {
            KeyCheck::Live("ik-test".into())
        }))
    }
}

/// Takes any client certificate, as Confidential Cloud does, and keeps the
/// key of the last one so a test can see what the gateway presented.
#[derive(Debug)]
struct AnyCertificate {
    provider: Arc<CryptoProvider>,
    presented: Arc<Mutex<Vec<u8>>>,
}

impl ClientCertVerifier for AnyCertificate {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let (_, parsed) = x509_parser::parse_x509_certificate(end_entity.as_ref())
            .map_err(|_| rustls::Error::General("not a certificate".into()))?;
        *self.presented.lock().unwrap_or_else(|_| unreachable!()) =
            parsed.public_key().raw.to_vec();
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The usage path: while `unbound`, `401`; a report of more than
/// `max_report` requests, `413`; one with a request of key `ik-poison`,
/// `400`; otherwise each request of key `ik-unknown` is refused in the
/// answer and the rest stored.
#[derive(Default)]
struct Cloud {
    recorded: Mutex<Vec<Value>>,
    unbound: AtomicBool,
    max_report: AtomicUsize,
    presented: Arc<Mutex<Vec<u8>>>,
}

async fn usage(State(cloud): State<Arc<Cloud>>, Json(body): Json<Value>) -> impl IntoResponse {
    if cloud.unbound.load(Ordering::SeqCst) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let requests = body["requests"].as_array().cloned().unwrap_or_default();
    let max = cloud.max_report.load(Ordering::SeqCst);
    if max > 0 && requests.len() > max {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    if requests.iter().any(|request| request["key"] == "ik-poison") {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (refused, stored): (Vec<_>, Vec<_>) = requests
        .into_iter()
        .partition(|request| request["key"] == "ik-unknown");
    cloud
        .recorded
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .extend(stored);
    let refused: Vec<_> = refused
        .iter()
        .map(|request| json!({"id": request["id"], "reason": "unknown_key"}))
        .collect();
    Json(json!({ "refused": refused })).into_response()
}

fn start_cloud(cloud: Arc<Cloud>) -> Result<UsageClient, Box<dyn std::error::Error>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let _ = (*provider).clone().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["usage.test".to_owned()])?;
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AnyCertificate {
            provider,
            presented: cloud.presented.clone(),
        }))
        .with_single_cert(
            vec![certified.cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into()),
        )?;
    let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server));
    let app = Router::new()
        .route(USAGE_PATH, post(usage))
        .with_state(cloud);
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    tokio::spawn(axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service()));
    Ok(UsageClient::new(&usage_client::Config {
        origin: format!("https://usage.test:{}", address.port()),
        identity_pem: ReporterKey::from_secret(&SECRET)?.identity_pem().to_owned(),
        tls_ca_pem: Some(certified.cert.pem()),
        connect_address: Some("127.0.0.1".parse()?),
    })?)
}

async fn start_upstream() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let app = Router::new().route("/v1/chat/completions", post(|Json(payload): Json<Value>| async move {
            if payload["stream"] == true {
                assert_eq!(payload["stream_options"]["include_usage"], true);
                let text = "data: {\"model\":\"model-a\",\"choices\":[{\"delta\":{\"content\":\"private-output\"}}]}\n\ndata: {\"model\":\"model-a\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":5,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\ndata: [DONE]\n\n";
                ([(header::CONTENT_TYPE, "text/event-stream")], Body::from(Bytes::from_static(text.as_bytes()))).into_response()
            } else {
                Json(json!({"model":"model-a","choices":[{"message":{"content":"private-output"}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":4}}})).into_response()
            }
        }));
        axum::serve(listener, app).await
    });
    Ok(address)
}

fn recorder(capacity: usize, metrics: &Arc<GatewayMetrics>) -> Arc<Recorder> {
    let models = BTreeMap::from([(
        "model-a".to_owned(),
        Model {
            served_model: "model-a".into(),
            model_revision: "revision-1".into(),
        },
    )]);
    Recorder::new("us-west-1", models, capacity, metrics.clone())
}

async fn gateway(
    recorder: &Arc<Recorder>,
    metrics: &Arc<GatewayMetrics>,
) -> Result<Router, Box<dyn std::error::Error>> {
    let upstream = start_upstream().await?;
    Ok(router_with_usage(
        GatewayConfig {
            catalog_model_ids: vec!["model-a".into()],
            inference_model_ids: vec!["model-a".into()],
            upstream_base_url: format!("http://{upstream}"),
            maximum_body_bytes: 4096,
            upstream_timeout: Duration::from_secs(5),
            protection: ProtectionConfig::default(),
        },
        Arc::new(Keys),
        Arc::new(Audit),
        metrics.clone(),
        reqwest::Client::new(),
        Some(recorder.clone()),
    ))
}

async fn complete(
    app: &Router,
    bearer: &str,
    streaming: bool,
) -> Result<(StatusCode, Value), Box<dyn std::error::Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/chat/completions")
                .method("POST")
                .header("authorization", format!("Bearer {bearer}"))
                .header("content-type", "application/json")
                .header("x-request-id", "caller-chosen-id")
                .body(Body::from(
                    json!({"model":"model-a","messages":[{"role":"user","content":"private-prompt"}],"stream":streaming})
                        .to_string(),
                ))?,
        )
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 16).await?;
    Ok((status, serde_json::from_slice(&body).unwrap_or(Value::Null)))
}

fn counter(metrics: &GatewayMetrics, line_prefix: &str) -> u64 {
    metrics
        .render_prometheus()
        .lines()
        .find(|line| line.starts_with(line_prefix))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn add(recorder: &Arc<Recorder>, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut request = recorder
        .reserve(key, "model-a")
        .map_err(|unrecorded| format!("{unrecorded:?}"))?;
    request.observation.input = Some(3);
    request.observation.output = Some(1);
    request.finish(Outcome::Completed);
    Ok(())
}

#[tokio::test]
async fn served_requests_reach_cloud_under_the_reporter_certificate()
-> Result<(), Box<dyn std::error::Error>> {
    let cloud = Arc::new(Cloud::default());
    let client = start_cloud(cloud.clone())?;
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let recorder = recorder(MAX_PENDING_EVENTS, &metrics);
    let app = gateway(&recorder, &metrics).await?;
    for streaming in [false, true] {
        assert_eq!(complete(&app, "live", streaming).await?.0, StatusCode::OK);
    }
    assert_eq!(recorder.pending(), 2);

    // Unbound: Cloud answers 401 and the events stay spooled.
    cloud.unbound.store(true, Ordering::SeqCst);
    assert_eq!(recorder.send_pending(&client).await, Err("unauthorized"));
    assert_eq!(recorder.pending(), 2);
    assert_eq!(
        counter(
            &metrics,
            "gateway_usage_send_failed_total{reason=\"unauthorized\""
        ),
        1
    );
    cloud.unbound.store(false, Ordering::SeqCst);
    recorder.send_pending(&client).await?;
    assert_eq!(recorder.pending(), 0);

    let key = ReporterKey::from_secret(&SECRET)?;
    assert_eq!(
        *cloud.presented.lock().unwrap_or_else(|_| unreachable!()),
        pem::parse(key.public_key_pem())?.contents()
    );
    let stored = cloud
        .recorded
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .clone();
    assert_eq!(stored.len(), 2);
    for request in &stored {
        let mut fields: Vec<_> = request
            .as_object()
            .ok_or("not an object")?
            .keys()
            .cloned()
            .collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "cachedInputTokens",
                "finishedAt",
                "id",
                "inputTokens",
                "key",
                "location",
                "model",
                "outputTokens",
                "startedAt"
            ]
        );
        assert_eq!(request["key"], "ik-test");
        assert_eq!(request["model"], "model-a");
        assert_eq!(request["location"], "us-west-1");
        assert_eq!(request["inputTokens"], 6);
        assert_eq!(request["cachedInputTokens"], 4);
        assert_eq!(request["outputTokens"], 5);
        assert_ne!(request["id"], "caller-chosen-id");
    }
    assert_ne!(stored[0]["id"], stored[1]["id"]);
    let text = serde_json::to_string(&stored)?;
    assert!(!text.contains("private-"));
    Ok(())
}

#[tokio::test]
async fn refusals_are_counted_and_a_refused_report_is_split_down_to_its_bad_request()
-> Result<(), Box<dyn std::error::Error>> {
    let cloud = Arc::new(Cloud::default());
    cloud.max_report.store(3, Ordering::SeqCst);
    let client = start_cloud(cloud.clone())?;
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let recorder = recorder(MAX_PENDING_EVENTS, &metrics);
    for key in [
        "ik-1",
        "ik-2",
        "ik-poison",
        "ik-3",
        "ik-unknown",
        "ik-4",
        "ik-5",
    ] {
        add(&recorder, key)?;
    }
    // 413 above 3 requests and 400 for a report with the poison request:
    // neither blocks the spool.
    recorder.send_pending(&client).await?;
    assert_eq!(recorder.pending(), 0);
    let stored: Vec<_> = cloud
        .recorded
        .lock()
        .unwrap_or_else(|_| unreachable!())
        .iter()
        .map(|request| request["key"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(stored, ["ik-1", "ik-2", "ik-3", "ik-4", "ik-5"]);
    assert_eq!(
        counter(
            &metrics,
            "gateway_usage_events_refused_total{reason=\"invalid\""
        ),
        1
    );
    assert_eq!(
        counter(
            &metrics,
            "gateway_usage_events_refused_total{reason=\"unknown_key\""
        ),
        1
    );
    Ok(())
}

#[tokio::test]
async fn a_full_spool_stops_serving_and_nothing_served_is_dropped()
-> Result<(), Box<dyn std::error::Error>> {
    // Nothing listens at the usage address, as when Cloud is unreachable.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")?.local_addr()?;
    let ca = rcgen::generate_simple_self_signed(vec!["usage.test".to_owned()])?
        .cert
        .pem();
    let client = UsageClient::new(&usage_client::Config {
        origin: format!("https://usage.test:{}", closed.port()),
        identity_pem: ReporterKey::from_secret(&SECRET)?.identity_pem().to_owned(),
        tls_ca_pem: Some(ca),
        connect_address: Some("127.0.0.1".parse()?),
    })?;
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let recorder = recorder(2, &metrics);
    let app = gateway(&recorder, &metrics).await?;
    assert_eq!(complete(&app, "live", false).await?.0, StatusCode::OK);
    assert_eq!(complete(&app, "live", true).await?.0, StatusCode::OK);
    let (status, body) = complete(&app, "live", false).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "usage_backlog_full");

    assert_eq!(recorder.send_pending(&client).await, Err("unreachable"));
    assert_eq!(recorder.pending(), 2);
    assert_eq!(counter(&metrics, "gateway_usage_backlog_full_total"), 1);
    Ok(())
}

#[tokio::test]
async fn an_org_out_of_credits_gets_insufficient_quota_and_the_key_is_served()
-> Result<(), Box<dyn std::error::Error>> {
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let recorder = recorder(MAX_PENDING_EVENTS, &metrics);
    let app = gateway(&recorder, &metrics).await?;
    let (status, body) = complete(&app, "broke", false).await?;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "insufficient_quota");
    assert_eq!(recorder.pending(), 0);

    let key = ReporterKey::from_secret(&SECRET)?;
    let response = reporter_key_router(key.public_key_pem().to_owned())
        .oneshot(
            Request::builder()
                .uri("/usage-reporter-key")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert_eq!(body, key.public_key_pem().as_bytes());
    Ok(())
}
