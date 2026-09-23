use std::time::Duration;

use axum_server::Handle;
use maintenance_gateway::app;

#[tokio::test]
async fn serves_plain_http_behind_c8s_tls_lb() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("test listener failed: {error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("test address failed: {error}"));
    let handle = Handle::new();
    let server_handle = handle.clone();
    let server = tokio::spawn(async move {
        axum_server::from_tcp(listener)
            .handle(server_handle)
            .serve(app().into_make_service())
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap_or_else(|error| panic!("test client failed: {error}"));
    let response = client
        .get(format!("http://127.0.0.1:{}/v1/models", address.port()))
        .send()
        .await
        .unwrap_or_else(|error| panic!("HTTP request failed: {error}"));
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .json::<serde_json::Value>()
            .await
            .unwrap_or_default(),
        serde_json::json!({
            "object":"list",
            "data":[
                {"id":"deepseek-ai/DeepSeek-V4-Flash-0731","object":"model","owned_by":"confidential.ai"}
            ]
        })
    );

    handle.shutdown();
    let _ = server.await;
}
