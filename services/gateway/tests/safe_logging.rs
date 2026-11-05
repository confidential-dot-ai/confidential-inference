#![allow(clippy::unwrap_used)]
use confidential_gateway::{
    AuditEvent, AuditSink, TracingAuditSink,
    safe_logging::{SafeLayer, emit},
};
use serde_json::json;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct NeverFormat;
impl std::fmt::Debug for NeverFormat {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        panic!("raw fields must not be formatted")
    }
}

#[test]
fn legacy_dependency_logs_spans_and_malformed_events_cannot_reach_stdout() {
    let output = Capture::default();
    let subscriber =
        tracing_subscriber::registry().with(SafeLayer::new(None, Box::new(output.clone())));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("PRIVATE_SPAN", request = "PRIVATE_REQUEST");
        let _entered = span.enter();
        tracing::error!(secret = ?NeverFormat, "PRIVATE_ERROR");
        tracing::error!(target: "ci.safe", secret = ?NeverFormat, "PRIVATE_FORGED_RECORD");
        tracing::info!(target: "ci.safe", safe_record = "PRIVATE_INVALID_JSON");
        emit("gateway_ready", json!({"prompt":"PRIVATE_PROMPT"}));
        emit("gateway_usage_rejected", json!({"status":true}));
        emit(
            "gateway_snapshot_fetch_failed",
            json!({"reason":"PRIVATE_EXCEPTION"}),
        );
        emit("gateway_ready", json!({}));
        TracingAuditSink.record(AuditEvent {
            request_id: "PRIVATE_CALLER_ID".into(),
            key_id: Some("PRIVATE_KEY_ID".into()),
            route: "/v1/chat/completions",
            status: 400,
        });
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while !String::from_utf8_lossy(&output.0.lock().unwrap()).contains("gateway_response_started")
        && std::time::Instant::now() < deadline
    {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let bytes = output.0.lock().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("PRIVATE"));
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["event"], "gateway_ready");
    assert_eq!(records[1]["status"], 400);
}

struct Broken;
impl Write for Broken {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("PRIVATE_SINK_FAILURE"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn a_failed_stdout_writer_has_no_raw_fallback() {
    let subscriber = tracing_subscriber::registry().with(SafeLayer::new(None, Box::new(Broken)));
    tracing::subscriber::with_default(subscriber, || emit("gateway_ready", json!({})));
}

#[test]
fn a_stalled_stdout_pipe_drops_records_without_blocking_the_request_thread() {
    struct Stalled(std::sync::mpsc::Receiver<()>);
    impl Write for Stalled {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let (release, blocked) = std::sync::mpsc::channel();
    let subscriber =
        tracing_subscriber::registry().with(SafeLayer::new(None, Box::new(Stalled(blocked))));
    let (before, _) = confidential_gateway::safe_logging::discarded_records();
    let started = std::time::Instant::now();
    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..1000 {
            emit("gateway_ready", json!({}));
        }
    });
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert!(confidential_gateway::safe_logging::discarded_records().0 > before);
    drop(release);
}

#[test]
fn startup_errors_do_not_echo_arguments_environment_or_exporter_errors() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_confidential-gateway"))
        .env_clear()
        .env("RUST_BACKTRACE", "full")
        .env(
            "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
            "PRIVATE_INVALID_EXPORTER_ENDPOINT",
        )
        .args(["--PRIVATE_INVALID_ARGUMENT", "PRIVATE_ARGUMENT_VALUE"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(!text.contains("PRIVATE"));
    assert!(text.contains("gateway_startup_failed"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE"));
}
