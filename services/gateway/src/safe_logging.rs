//! Application event contract. Validate before stdout and the OTLP queue.
use opentelemetry::logs::{LogRecord, Logger, LoggerProvider, Severity};
use serde_json::{Value, json};
use std::{
    io::Write,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{SyncSender, sync_channel},
    },
};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context};

static DROPPED_STDOUT: AtomicU64 = AtomicU64::new(0);
static REJECTED_RECORDS: AtomicU64 = AtomicU64::new(0);

/// Process counters contain no input values.
#[must_use]
pub fn discarded_records() -> (u64, u64) {
    (
        DROPPED_STDOUT.load(Ordering::Relaxed),
        REJECTED_RECORDS.load(Ordering::Relaxed),
    )
}

fn contract() -> &'static Value {
    static CONTRACT: OnceLock<Value> = OnceLock::new();
    CONTRACT.get_or_init(|| {
        serde_json::from_str(include_str!("safe_events.json")).unwrap_or(Value::Null)
    })
}

/// Reject unknown events and fields. Never return the rejected input.
#[must_use]
pub fn validate(record: &Value) -> bool {
    let Some(fields) = record.as_object() else {
        return false;
    };
    let Some(event) = record["event"].as_str() else {
        return false;
    };
    let spec = &contract()["events"][event];
    if record["schema_version"].as_i64() != Some(1)
        || record["component"] != spec["component"]
        || spec.is_null()
    {
        return false;
    }
    let Some(allowed) = spec["fields"].as_array() else {
        return false;
    };
    let Some(required) = spec["required"].as_array() else {
        return false;
    };
    if required
        .iter()
        .any(|name| name.as_str().is_none_or(|name| !fields.contains_key(name)))
    {
        return false;
    }
    for (name, value) in fields {
        if ["schema_version", "component", "event"].contains(&name.as_str()) {
            continue;
        }
        if !allowed.contains(&json!(name)) {
            return false;
        }
        let rule = &contract()["field_types"][name];
        if let Some(values) = rule["enum"].as_array() {
            if !value.is_string() || !values.contains(value) {
                return false;
            }
        } else {
            let Some(number) = value.as_i64() else {
                return false;
            };
            if rule["min"].as_i64().is_none_or(|min| number < min)
                || rule["max"].as_i64().is_none_or(|max| number > max)
            {
                return false;
            }
        }
    }
    serde_json::to_vec(record).is_ok_and(|bytes| bytes.len() <= 4096)
}

/// Existing application sites use this function. Customer identifiers are not accepted.
pub fn emit(event: &'static str, fields: Value) {
    let Value::Object(mut record) = fields else {
        return;
    };
    record.insert("event".into(), json!(event));
    record.insert("schema_version".into(), json!(1));
    record.insert("component".into(), json!("gateway"));
    let value = Value::Object(record);
    if validate(&value)
        && let Ok(body) = serde_json::to_string(&value)
    {
        tracing::info!(target: "ci.safe", safe_record = body.as_str());
    } else {
        REJECTED_RECORDS.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct RecordVisitor {
    body: Option<String>,
}
impl Visit for RecordVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "safe_record" && value.len() <= 4096 {
            self.body = Some(value.to_owned());
        }
    }
    fn record_debug(&mut self, _: &Field, _: &dyn std::fmt::Debug) {}
}

/// No formatter, span fields, dependency text, or SDK errors enter either sink.
/// The SDK has a bounded batch queue. Delivery failures never print the batch.
pub struct SafeLayer {
    output: SyncSender<String>,
    logger: Option<opentelemetry_sdk::logs::SdkLogger>,
}
impl SafeLayer {
    #[must_use]
    pub fn new(
        provider: Option<&opentelemetry_sdk::logs::SdkLoggerProvider>,
        output: Box<dyn Write + Send>,
    ) -> Self {
        let (sender, receiver) = sync_channel::<String>(256);
        // A stalled container pipe cannot block inference or OTLP delivery.
        std::thread::spawn(move || {
            let mut output = output;
            while let Ok(body) = receiver.recv() {
                if writeln!(output, "{body}").is_err() {
                    DROPPED_STDOUT.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        Self {
            output: sender,
            logger: provider.map(|p| p.logger("ci.safe.v1")),
        }
    }
}
impl<S: Subscriber> Layer<S> for SafeLayer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() != "ci.safe" {
            return;
        }
        let mut visitor = RecordVisitor::default();
        event.record(&mut visitor);
        let Some(body) = visitor.body else {
            return;
        };
        let Ok(value) = serde_json::from_str::<Value>(&body) else {
            return;
        };
        if !validate(&value) {
            return;
        }
        if self.output.try_send(body.clone()).is_err() {
            DROPPED_STDOUT.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(logger) = &self.logger {
            let mut record = logger.create_log_record();
            record.set_body(body.into());
            record.set_severity_number(Severity::Info);
            record.set_severity_text("INFO");
            record.set_trace_context(
                opentelemetry::trace::TraceId::INVALID,
                opentelemetry::trace::SpanId::INVALID,
                None,
            );
            logger.emit(record);
        }
    }
}
