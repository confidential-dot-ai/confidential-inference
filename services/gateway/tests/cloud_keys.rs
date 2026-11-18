//! Keys answered by a local HTTPS Confidential Cloud: live, refused, out of
//! credits, kept, kept while Cloud gives no answer, and never past a key's
//! expiry.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use confidential_gateway::{
    ApiKeyVerifier, KeyCheck,
    cloud_keys::{CloudKeys, Config, WHOAMI_PATH},
    metrics::{GatewayMetrics, MetricsSource},
};

fn key(c: char) -> String {
    format!("ci_{}", c.to_string().repeat(43))
}

/// A whoami: each listed key gets its listed status and body, any other
/// `401`. While `down`, every request gets `503`.
#[derive(Default)]
struct Cloud {
    answers: Mutex<HashMap<String, (StatusCode, String)>>,
    down: AtomicBool,
    served: AtomicUsize,
}

impl Cloud {
    fn answer(&self, key: &str, status: StatusCode, body: &str) {
        self.answers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_owned(), (status, body.to_owned()));
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

async fn start_cloud(
    cloud: Arc<Cloud>,
) -> Result<(SocketAddr, String), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["cloud.test".to_owned()])?;
    let certificate = certified.cert.pem();
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate.clone().into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
    )
    .await?;
    let app = Router::new().route(
        WHOAMI_PATH,
        get(move |headers: HeaderMap| async move {
            cloud.served.fetch_add(1, Ordering::SeqCst);
            if cloud.down.load(Ordering::SeqCst) {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            let bearer = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or_default();
            let answer = cloud
                .answers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(bearer)
                .cloned();
            match answer {
                Some((status, body)) => (status, body).into_response(),
                None => StatusCode::UNAUTHORIZED.into_response(),
            }
        }),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    tokio::spawn(axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service()));
    Ok((address, certificate))
}

fn checks(metrics: &GatewayMetrics, result: &str) -> u64 {
    let label = format!("result=\"{result}\"");
    metrics
        .render_prometheus()
        .lines()
        .find(|line| line.starts_with("gateway_cloud_key_checks_total{") && line.contains(&label))
        .and_then(|line| line.rsplit(' ').next())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

async fn keys(
    cloud: Arc<Cloud>,
    answer_ttl: Duration,
    stale_ttl: Duration,
) -> Result<(CloudKeys, Arc<GatewayMetrics>), Box<dyn std::error::Error>> {
    let (address, ca) = start_cloud(cloud).await?;
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    let mut config = Config::new(format!("https://cloud.test:{}", address.port()));
    config.tls_ca_pem = Some(ca);
    config.connect_address = Some("127.0.0.1".parse()?);
    config.answer_ttl = answer_ttl;
    config.stale_ttl = stale_ttl;
    Ok((CloudKeys::new(&config, metrics.clone())?, metrics))
}

const LIVE: &str = r#"{"keyId":"ik-live","orgId":"org-1"}"#;

#[tokio::test]
async fn cloud_decides_and_its_answers_are_kept() -> Result<(), Box<dyn std::error::Error>> {
    let cloud = Arc::new(Cloud::default());
    let (live, unknown, limited, failing) = (key('a'), key('b'), key('c'), key('d'));
    cloud.answer(&live, StatusCode::OK, LIVE);
    cloud.answer(&limited, StatusCode::TOO_MANY_REQUESTS, "");
    cloud.answer(&failing, StatusCode::INTERNAL_SERVER_ERROR, "");
    let (keys, metrics) = keys(
        cloud.clone(),
        Duration::from_secs(60),
        Duration::from_secs(600),
    )
    .await?;

    assert_eq!(keys.check(&live).await, KeyCheck::Live("ik-live".into()));
    assert_eq!(keys.check(&unknown).await, KeyCheck::Refused);
    assert_eq!(keys.check(&limited).await, KeyCheck::Refused);
    assert_eq!(keys.check(&failing).await, KeyCheck::Unavailable);
    assert_eq!(cloud.served(), 4);
    // Not of an inference key's form: refused without a request.
    assert_eq!(
        keys.check("sk-not-an-inference-key").await,
        KeyCheck::Refused
    );
    assert_eq!(cloud.served(), 4);

    // Answers are kept; a check that got none is asked again.
    assert_eq!(keys.check(&live).await, KeyCheck::Live("ik-live".into()));
    assert_eq!(keys.check(&unknown).await, KeyCheck::Refused);
    assert_eq!(keys.check(&failing).await, KeyCheck::Unavailable);
    assert_eq!(cloud.served(), 5);
    assert_eq!(checks(&metrics, "live"), 1);
    assert_eq!(checks(&metrics, "refused"), 2);
    assert_eq!(checks(&metrics, "kept"), 2);
    assert_eq!(checks(&metrics, "unavailable"), 2);
    Ok(())
}

#[tokio::test]
async fn a_live_key_outlasts_an_outage_but_not_the_stale_time_or_its_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let cloud = Arc::new(Cloud::default());
    let (live, expiring, revoked) = (key('a'), key('b'), key('c'));
    cloud.answer(&live, StatusCode::OK, LIVE);
    let soon = time::OffsetDateTime::now_utc() + time::Duration::milliseconds(300);
    let soon = soon.format(&time::format_description::well_known::Rfc3339)?;
    cloud.answer(
        &expiring,
        StatusCode::OK,
        &format!(r#"{{"keyId":"ik-expiring","orgId":"org-1","expiresAt":"{soon}"}}"#),
    );
    cloud.answer(
        &revoked,
        StatusCode::OK,
        r#"{"keyId":"ik-revoked","orgId":"org-1"}"#,
    );
    let (keys, metrics) = keys(
        cloud.clone(),
        Duration::from_millis(100),
        Duration::from_millis(1_000),
    )
    .await?;
    for key in [&live, &expiring, &revoked] {
        assert!(matches!(keys.check(key).await, KeyCheck::Live(_)));
    }

    // Revoked in Cloud: refused once the kept answer is past its time.
    cloud.answer(&revoked, StatusCode::UNAUTHORIZED, "");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(keys.check(&revoked).await, KeyCheck::Refused);

    // Cloud is down: a key answered live within the stale time stays live.
    cloud.down.store(true, Ordering::SeqCst);
    assert_eq!(keys.check(&live).await, KeyCheck::Live("ik-live".into()));
    assert_eq!(checks(&metrics, "stale"), 1);
    // ...but never past its own expiry, nor past the stale time.
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(keys.check(&expiring).await, KeyCheck::Unavailable);
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(keys.check(&live).await, KeyCheck::Unavailable);
    Ok(())
}

#[tokio::test]
async fn an_org_out_of_credits_is_refused_until_it_tops_up_and_never_served_stale()
-> Result<(), Box<dyn std::error::Error>> {
    let cloud = Arc::new(Cloud::default());
    let broke = key('a');
    cloud.answer(&broke, StatusCode::OK, LIVE);
    let (keys, metrics) = keys(
        cloud.clone(),
        Duration::from_millis(100),
        Duration::from_secs(600),
    )
    .await?;
    assert!(matches!(keys.check(&broke).await, KeyCheck::Live(_)));

    cloud.answer(&broke, StatusCode::PAYMENT_REQUIRED, "");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(keys.check(&broke).await, KeyCheck::OutOfCredits);
    assert_eq!(keys.check(&broke).await, KeyCheck::OutOfCredits);
    assert_eq!(checks(&metrics, "out_of_credits"), 1);

    // Cloud is down: the earlier live answer is not used.
    cloud.down.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(keys.check(&broke).await, KeyCheck::Unavailable);

    // Topped up: live again once the kept answer is past its time.
    cloud.down.store(false, Ordering::SeqCst);
    cloud.answer(&broke, StatusCode::OK, LIVE);
    assert_eq!(keys.check(&broke).await, KeyCheck::Live("ik-live".into()));
    Ok(())
}

#[test]
fn only_a_plain_https_origin_is_accepted() {
    let metrics = Arc::new(GatewayMetrics::new("staging"));
    for origin in [
        "http://cloud.test",
        "https://user@cloud.test",
        "https://cloud.test/inference",
        "https://cloud.test/?a=b",
        "not a url",
    ] {
        let config = Config::new(origin.to_owned());
        assert!(
            CloudKeys::new(&config, metrics.clone()).is_err(),
            "{origin}"
        );
    }
    assert!(CloudKeys::new(&Config::new("https://cloud.test".to_owned()), metrics).is_ok());
}
