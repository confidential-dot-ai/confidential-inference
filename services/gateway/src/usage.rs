//! Per-request usage events, kept in memory and sent to the admin.
//!
//! After each request the gateway records one immutable event: a fresh
//! `request_id`, the key ID, the requested model, the outcome and the token
//! counts. Request bodies, headers, addresses and credentials are never part
//! of an event. Events wait in a bounded in-memory queue and are sent in
//! batches (`crate::admin_client`). An event leaves the queue only after the
//! admin acknowledged its batch; the admin stores each `request_id` once, so
//! a batch may be sent again after any failure.
//!
//! When the queue is full the oldest event is dropped, the request is still
//! served, and `gateway_usage_events_dropped_total` grows. On shutdown the
//! gateway sends what is left, within a deadline.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{admin_client::AdminClient, metrics::GatewayMetrics};

/// About 250 bytes per event, so a full queue holds about 25 MiB.
pub const MAX_PENDING_EVENTS: usize = 100_000;
/// The largest batch: about 125 KiB of JSON.
pub const MAX_BATCH_EVENTS: usize = 500;
const SEND_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RETRY_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Model {
    pub served_model: String,
    pub model_revision: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Observation {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub cached: Option<u64>,
    pub reasoning: Option<u64>,
    pub final_usage: bool,
}

/// One completed request.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Event {
    /// A fresh random UUID per event, never the caller's `x-request-id`, so a
    /// caller cannot make two of its requests collide.
    pub request_id: String,
    pub key_id: String,
    pub requested_model: String,
    pub outcome: Outcome,
    pub final_usage: bool,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub reasoning_tokens: Option<u64>,
    pub ended_at_ms: u64,
    /// The gateway pod that served the request.
    pub producer_instance: String,
}

struct Queue {
    events: VecDeque<(u64, Event)>,
    next_sequence: u64,
}

pub struct Recorder {
    producer_instance: String,
    models: BTreeMap<String, Model>,
    capacity: usize,
    metrics: Arc<GatewayMetrics>,
    queue: Mutex<Queue>,
}

#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| {
            u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
        })
}

impl Recorder {
    /// `models` maps each requested model to the backend model whose
    /// response may supply its usage.
    #[must_use]
    pub fn new(
        producer_instance: &str,
        models: BTreeMap<String, Model>,
        capacity: usize,
        metrics: Arc<GatewayMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            producer_instance: producer_instance.to_owned(),
            models,
            capacity,
            metrics,
            queue: Mutex::new(Queue {
                events: VecDeque::new(),
                next_sequence: 0,
            }),
        })
    }

    /// Start the usage record of one request. The event is recorded when the
    /// returned guard drops. `None` for a model the usage configuration does
    /// not name.
    #[must_use]
    pub fn reserve(self: &Arc<Self>, key_id: &str, requested_model: &str) -> Option<RequestUsage> {
        let model = self.models.get(requested_model)?.clone();
        Some(RequestUsage {
            recorder: self.clone(),
            key_id: key_id.to_owned(),
            requested_model: requested_model.to_owned(),
            model,
            observation: Observation::default(),
            outcome: Outcome::Cancelled,
            ended_at: None,
        })
    }

    fn push(&self, event: Event) {
        let mut queue = self.lock();
        if queue.events.len() >= self.capacity {
            queue.events.pop_front();
            self.metrics.record_usage_event_dropped();
            tracing::error!("the usage queue is full; dropped the oldest event");
        }
        let sequence = queue.next_sequence;
        queue.next_sequence += 1;
        queue.events.push_back((sequence, event));
        self.metrics.set_usage_events_pending(queue.events.len());
    }

    /// The oldest events, at most `limit`, and the sequence of the last one.
    #[must_use]
    pub fn batch(&self, limit: usize) -> Option<(u64, Vec<Event>)> {
        let queue = self.lock();
        let events: Vec<_> = queue.events.iter().take(limit).collect();
        let last = events.last()?.0;
        Some((
            last,
            events.into_iter().map(|(_, event)| event.clone()).collect(),
        ))
    }

    /// Remove every event up to `last_sequence`. Events dropped from a full
    /// queue meanwhile are simply gone.
    pub fn acknowledge(&self, last_sequence: u64) {
        let mut queue = self.lock();
        while queue
            .events
            .front()
            .is_some_and(|(sequence, _)| *sequence <= last_sequence)
        {
            queue.events.pop_front();
        }
        self.metrics.set_usage_events_pending(queue.events.len());
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        self.lock().events.len()
    }

    /// Send queued events in batches until the queue is empty or a send
    /// fails.
    ///
    /// # Errors
    ///
    /// Returns the reason code of the failed send.
    pub async fn send_pending(&self, client: &AdminClient) -> Result<(), &'static str> {
        while let Some((last, events)) = self.batch(MAX_BATCH_EVENTS) {
            if let Err(reason) = client.send_events(&events).await {
                self.metrics.record_usage_send_failure(reason);
                return Err(reason);
            }
            self.acknowledge(last);
        }
        Ok(())
    }

    /// Send queued events every 5 s, backing off to 60 s while the admin
    /// fails.
    pub async fn deliver(self: Arc<Self>, client: Arc<AdminClient>) {
        let mut delay = SEND_INTERVAL;
        loop {
            tokio::time::sleep(delay).await;
            delay = match self.send_pending(&client).await {
                Ok(()) => SEND_INTERVAL,
                Err(reason) => {
                    tracing::warn!(reason, pending = self.pending(), "usage delivery delayed");
                    (delay * 2).min(MAX_RETRY_INTERVAL)
                }
            };
        }
    }

    /// Send what is left before the process exits, retrying until `timeout`.
    pub async fn flush(&self, client: &AdminClient, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while self.pending() > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if tokio::time::timeout(remaining, self.send_pending(client)).await == Ok(Ok(())) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1).min(remaining)).await;
        }
        let pending = self.pending();
        if pending > 0 {
            tracing::error!(pending, "usage events were not delivered before shutdown");
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The usage record of one request. Dropping it records the event, so a
/// client that goes away still produces a `cancelled` event.
pub struct RequestUsage {
    recorder: Arc<Recorder>,
    key_id: String,
    requested_model: String,
    model: Model,
    pub observation: Observation,
    outcome: Outcome,
    ended_at: Option<u64>,
}

impl RequestUsage {
    #[must_use]
    pub fn served_model(&self) -> &str {
        &self.model.served_model
    }

    pub fn finish(&mut self, outcome: Outcome) {
        self.outcome = outcome;
        self.ended_at = Some(now_ms());
    }
}

impl Drop for RequestUsage {
    fn drop(&mut self) {
        let observation = self.observation;
        self.recorder.push(Event {
            request_id: uuid::Uuid::new_v4().to_string(),
            key_id: std::mem::take(&mut self.key_id),
            requested_model: std::mem::take(&mut self.requested_model),
            outcome: self.outcome,
            final_usage: observation.final_usage,
            input_tokens: observation.input,
            output_tokens: observation.output,
            cached_input_tokens: observation.cached,
            reasoning_tokens: observation.reasoning,
            ended_at_ms: self.ended_at.unwrap_or_else(now_ms),
            producer_instance: self.recorder.producer_instance.clone(),
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::metrics::MetricsSource;

    fn recorder(capacity: usize) -> (Arc<Recorder>, Arc<GatewayMetrics>) {
        let metrics = Arc::new(GatewayMetrics::new("staging"));
        let models = BTreeMap::from([(
            "model-a".into(),
            Model {
                served_model: "model-a".into(),
                model_revision: "revision-1".into(),
            },
        )]);
        (
            Recorder::new("gateway-0", models, capacity, metrics.clone()),
            metrics,
        )
    }

    fn complete(recorder: &Arc<Recorder>, key: &str, input: u64) {
        let mut request = recorder.reserve(key, "model-a").unwrap();
        request.observation = Observation {
            input: Some(input),
            output: Some(1),
            cached: None,
            reasoning: None,
            final_usage: true,
        };
        request.finish(Outcome::Completed);
    }

    #[test]
    fn each_request_is_one_event_with_a_fresh_request_id() {
        let (recorder, _) = recorder(16);
        complete(&recorder, "key_a", 10);
        complete(&recorder, "key_a", 20);
        drop(recorder.reserve("key_b", "model-a").unwrap());
        let (_, events) = recorder.batch(10).unwrap();
        assert_eq!(events.len(), 3);
        assert_ne!(events[0].request_id, events[1].request_id);
        assert_eq!(events[0].input_tokens, Some(10));
        assert_eq!(events[0].outcome, Outcome::Completed);
        assert_eq!(events[2].outcome, Outcome::Cancelled);
        assert_eq!(events[2].producer_instance, "gateway-0");
        assert!(recorder.reserve("key_a", "model-unknown").is_none());
    }

    #[test]
    fn acknowledge_removes_only_the_sent_events() {
        let (recorder, _) = recorder(16);
        complete(&recorder, "key_a", 1);
        complete(&recorder, "key_a", 2);
        let (last, events) = recorder.batch(1).unwrap();
        assert_eq!(events.len(), 1);
        complete(&recorder, "key_a", 3);
        recorder.acknowledge(last);
        let (_, left) = recorder.batch(10).unwrap();
        assert_eq!(
            left.iter()
                .map(|event| event.input_tokens)
                .collect::<Vec<_>>(),
            [Some(2), Some(3)]
        );
    }

    #[test]
    fn a_full_queue_drops_the_oldest_event_and_counts_it() {
        let (recorder, metrics) = recorder(2);
        for input in 1..=3 {
            complete(&recorder, "key_a", input);
        }
        let (_, events) = recorder.batch(10).unwrap();
        assert_eq!(
            events
                .iter()
                .map(|event| event.input_tokens)
                .collect::<Vec<_>>(),
            [Some(2), Some(3)]
        );
        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains("gateway_usage_events_dropped_total{env=\"staging\"} 1"),
            "{rendered}"
        );
        assert!(
            rendered.contains("gateway_usage_events_pending{env=\"staging\"} 2"),
            "{rendered}"
        );
    }

    #[test]
    fn an_event_holds_no_content_or_credential_fields() {
        let (recorder, _) = recorder(16);
        complete(&recorder, "key_a", 1);
        let (_, events) = recorder.batch(1).unwrap();
        let value = serde_json::to_value(&events[0]).unwrap();
        let mut fields: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        fields.sort();
        assert_eq!(
            fields,
            [
                "cached_input_tokens",
                "ended_at_ms",
                "final_usage",
                "input_tokens",
                "key_id",
                "outcome",
                "output_tokens",
                "producer_instance",
                "reasoning_tokens",
                "request_id",
                "requested_model",
            ]
        );
    }
}
