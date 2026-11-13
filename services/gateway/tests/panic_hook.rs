//! The gateway panic hook logs the location of a panic, never its message.
//!
//! The hook is global to the process, so this test has its own test binary.

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use confidential_gateway::log_privacy;
use tracing_subscriber::layer::SubscriberExt;

const CANARY: &str = "CANARY_PANIC_PAYLOAD_51c0";

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_panic_message_is_never_logged() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || writer.clone()),
    );
    log_privacy::install_panic_hook();
    tracing::subscriber::with_default(subscriber, || {
        let result = std::panic::catch_unwind(|| {
            let request = format!("{{\"prompt\":\"{CANARY}\"}}");
            panic!("could not handle {request}");
        });
        assert!(result.is_err());
    });
    let _ = std::panic::take_hook();
    let logs = String::from_utf8_lossy(
        &captured
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
    .into_owned();
    assert!(logs.contains("the gateway panicked"), "{logs}");
    assert!(logs.contains("panic_hook.rs"), "{logs}");
    assert!(!logs.contains(CANARY), "{logs}");
}
