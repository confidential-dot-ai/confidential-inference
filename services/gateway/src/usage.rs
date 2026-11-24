//! Per-request usage, kept in a bounded spool and reported to Confidential
//! Cloud.
//!
//! After each request the gateway records one immutable event: a fresh id,
//! the key's record ID, the requested model, the location, when it started
//! and finished, and its uncached input, cached input and output tokens.
//! Request bodies, headers, addresses and credentials are never part of an
//! event. Events wait in a bounded in-memory spool and are reported in
//! batches (`crate::usage_client`). An event leaves the spool only after
//! Confidential Cloud answered its report; it records each id once, so a
//! report may be sent again after any failure.
//!
//! The spool never drops a request it served. Its capacity counts the
//! requests in flight as well as those waiting, and a request that finds it
//! full is answered `503 usage_backlog_full` before it reaches a model. So
//! while Confidential Cloud refuses or cannot be reached, the gateway keeps
//! what it served and stops serving once it holds as much as it may.
//! `gateway_usage_events_pending` and `gateway_usage_send_failed_total` are
//! what an alert watches. On shutdown the gateway sends what is left, within
//! a deadline; a process that dies loses what it held.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use serde::{Deserialize, Serialize};

use crate::{
    metrics::GatewayMetrics,
    usage_client::{SendError, UsageClient},
};

/// About 300 bytes per event, so a full spool holds about 30 MiB.
pub const MAX_PENDING_EVENTS: usize = 100_000;
/// The largest report: about 150 KiB of JSON, within Confidential Cloud's
/// 1,000 requests and 1 MiB.
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

/// One served request, as Confidential Cloud takes it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// A fresh random UUID per event, never the caller's `x-request-id`, so a
    /// caller cannot make two of its requests collide.
    pub id: String,
    /// The key's record ID, as Confidential Cloud's whoami gave it.
    pub key: String,
    pub model: String,
    pub location: String,
    pub started_at: String,
    pub finished_at: String,
    /// Input tokens not read from the cache. The three counts never overlap.
    pub input_tokens: u64,
    pub cached_input_tokens: u64,
    pub output_tokens: u64,
    #[serde(skip)]
    pub outcome: Outcome,
    /// Whether the counts came from the response's final usage.
    #[serde(skip)]
    pub final_usage: bool,
}

/// Why a request cannot be served with its usage recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Unrecorded {
    /// The usage configuration does not name the requested model.
    UnknownModel,
    /// The spool holds as many requests as it may.
    Full,
}

struct Spool {
    events: VecDeque<(u64, Event)>,
    next_sequence: u64,
    in_flight: usize,
}

pub struct Recorder {
    location: String,
    models: BTreeMap<String, Model>,
    capacity: usize,
    metrics: Arc<GatewayMetrics>,
    spool: Mutex<Spool>,
}

fn rfc3339(at: SystemTime) -> String {
    time::OffsetDateTime::from(at)
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| unreachable!("a system time formats as RFC 3339"))
}

impl Recorder {
    /// `location` is where the gateway serves, as Confidential Cloud names
    /// it. `models` maps each requested model to the backend model whose
    /// response may supply its usage.
    #[must_use]
    pub fn new(
        location: &str,
        models: BTreeMap<String, Model>,
        capacity: usize,
        metrics: Arc<GatewayMetrics>,
    ) -> Arc<Self> {
        Arc::new(Self {
            location: location.to_owned(),
            models,
            capacity,
            metrics,
            spool: Mutex::new(Spool {
                events: VecDeque::new(),
                next_sequence: 0,
                in_flight: 0,
            }),
        })
    }

    /// Start the usage record of one request, which takes a place in the
    /// spool until its event is reported. The event is recorded when the
    /// returned guard drops.
    ///
    /// # Errors
    ///
    /// [`Unrecorded`] when the request must not be served.
    pub fn reserve(
        self: &Arc<Self>,
        key_id: &str,
        requested_model: &str,
    ) -> Result<RequestUsage, Unrecorded> {
        let model = self
            .models
            .get(requested_model)
            .ok_or(Unrecorded::UnknownModel)?
            .clone();
        {
            let mut spool = self.lock();
            if spool.events.len() + spool.in_flight >= self.capacity {
                self.metrics.record_usage_backlog_full();
                return Err(Unrecorded::Full);
            }
            spool.in_flight += 1;
        }
        Ok(RequestUsage {
            recorder: self.clone(),
            key_id: key_id.to_owned(),
            requested_model: requested_model.to_owned(),
            model,
            observation: Observation::default(),
            outcome: Outcome::Cancelled,
            started_at: SystemTime::now(),
            ended_at: None,
        })
    }

    /// Spool `event`, in the place its request held. An event of no tokens
    /// is not reported: it costs nothing, and Confidential Cloud refuses it.
    fn finish(&self, event: Event) {
        let mut spool = self.lock();
        spool.in_flight = spool.in_flight.saturating_sub(1);
        if event.input_tokens + event.cached_input_tokens + event.output_tokens > 0 {
            let sequence = spool.next_sequence;
            spool.next_sequence += 1;
            spool.events.push_back((sequence, event));
        }
        self.metrics.set_usage_events_pending(spool.events.len());
    }

    /// The oldest events, at most `limit`, and the sequence of the last one.
    #[must_use]
    pub fn batch(&self, limit: usize) -> Option<(u64, Vec<Event>)> {
        let spool = self.lock();
        let events: Vec<_> = spool.events.iter().take(limit).collect();
        let last = events.last()?.0;
        Some((
            last,
            events.into_iter().map(|(_, event)| event.clone()).collect(),
        ))
    }

    /// Remove every event up to `last_sequence`.
    pub fn acknowledge(&self, last_sequence: u64) {
        let mut spool = self.lock();
        while spool
            .events
            .front()
            .is_some_and(|(sequence, _)| *sequence <= last_sequence)
        {
            spool.events.pop_front();
        }
        self.metrics.set_usage_events_pending(spool.events.len());
    }

    #[must_use]
    pub fn pending(&self) -> usize {
        self.lock().events.len()
    }

    /// Report spooled events in batches until the spool is empty or a report
    /// fails in a way that can pass later.
    ///
    /// A request Confidential Cloud refuses in its answer is gone for good: it
    /// is counted by reason and logged. A report it refuses whole (400, 413)
    /// never blocks the spool: it is split in halves until the refused events
    /// stand alone, and each refused single event is dropped, counted and
    /// logged.
    ///
    /// # Errors
    ///
    /// Returns the reason code of a report that can pass later.
    pub async fn send_pending(&self, client: &UsageClient) -> Result<(), &'static str> {
        let mut limit = MAX_BATCH_EVENTS;
        while let Some((last, events)) = self.batch(limit) {
            match client.report(&events).await {
                Ok(refused) => {
                    self.acknowledge(last);
                    for refusal in refused {
                        self.metrics.record_usage_event_refused(&refusal.reason);
                        tracing::error!(
                            id = %refusal.id,
                            reason = %refusal.reason,
                            "a usage event was refused by Confidential Cloud"
                        );
                    }
                    limit = MAX_BATCH_EVENTS;
                }
                Err(SendError::Rejected(_)) if events.len() > 1 => limit = events.len() / 2,
                Err(SendError::Rejected(status)) => {
                    self.acknowledge(last);
                    self.metrics.record_usage_event_refused(match status {
                        413 => "too_large",
                        _ => "invalid",
                    });
                    tracing::error!(
                        status,
                        "a usage report was refused by Confidential Cloud; dropped it"
                    );
                    limit = MAX_BATCH_EVENTS;
                }
                Err(SendError::Retry(reason)) => {
                    self.metrics.record_usage_send_failure(reason);
                    return Err(reason);
                }
            }
        }
        Ok(())
    }

    /// Report spooled events every 5 s, backing off to 60 s while
    /// Confidential Cloud fails.
    pub async fn deliver(self: Arc<Self>, client: Arc<UsageClient>) {
        let mut delay = SEND_INTERVAL;
        loop {
            tokio::time::sleep(delay).await;
            delay = match self.send_pending(&client).await {
                Ok(()) => SEND_INTERVAL,
                Err(reason) => {
                    if reason == "unauthorized" {
                        tracing::error!(
                            pending = self.pending(),
                            "the reporter key is not bound in Confidential Cloud; bind the key the gateway serves"
                        );
                    } else {
                        tracing::warn!(reason, pending = self.pending(), "usage delivery delayed");
                    }
                    (delay * 2).min(MAX_RETRY_INTERVAL)
                }
            };
        }
    }

    /// Send what is left before the process exits, retrying until `timeout`.
    pub async fn flush(&self, client: &UsageClient, timeout: Duration) {
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
            tracing::error!(pending, "usage events were not reported before shutdown");
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Spool> {
        self.spool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The usage record of one request. Dropping it records the event, so a
/// client that goes away still produces one for what it used.
pub struct RequestUsage {
    recorder: Arc<Recorder>,
    key_id: String,
    requested_model: String,
    model: Model,
    pub observation: Observation,
    outcome: Outcome,
    started_at: SystemTime,
    ended_at: Option<SystemTime>,
}

impl RequestUsage {
    #[must_use]
    pub fn served_model(&self) -> &str {
        &self.model.served_model
    }

    pub fn finish(&mut self, outcome: Outcome) {
        self.outcome = outcome;
        self.ended_at = Some(SystemTime::now());
    }
}

impl Drop for RequestUsage {
    fn drop(&mut self) {
        let observation = self.observation;
        let cached = observation.cached.unwrap_or(0);
        let event = Event {
            id: uuid::Uuid::new_v4().to_string(),
            key: std::mem::take(&mut self.key_id),
            model: std::mem::take(&mut self.requested_model),
            location: self.recorder.location.clone(),
            started_at: rfc3339(self.started_at),
            finished_at: rfc3339(self.ended_at.unwrap_or_else(SystemTime::now)),
            // OpenAI-compatible input counts include the cached tokens.
            input_tokens: observation.input.unwrap_or(0).saturating_sub(cached),
            cached_input_tokens: cached,
            output_tokens: observation.output.unwrap_or(0),
            outcome: self.outcome,
            final_usage: observation.final_usage,
        };
        self.recorder.finish(event);
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
            Recorder::new("us-west-1", models, capacity, metrics.clone()),
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
    fn each_request_is_one_event_with_a_fresh_id() {
        let (recorder, _) = recorder(16);
        complete(&recorder, "ik-a", 10);
        complete(&recorder, "ik-a", 20);
        let mut cached = recorder.reserve("ik-b", "model-a").unwrap();
        cached.observation = Observation {
            input: Some(100),
            output: Some(5),
            cached: Some(60),
            reasoning: Some(2),
            final_usage: true,
        };
        drop(cached);
        let (_, events) = recorder.batch(10).unwrap();
        assert_eq!(events.len(), 3);
        assert_ne!(events[0].id, events[1].id);
        assert_eq!(events[0].input_tokens, 10);
        assert_eq!(events[0].outcome, Outcome::Completed);
        assert_eq!(events[0].location, "us-west-1");
        assert!(events[0].started_at <= events[0].finished_at);
        assert_eq!(
            (
                events[2].input_tokens,
                events[2].cached_input_tokens,
                events[2].output_tokens
            ),
            (40, 60, 5)
        );
        assert_eq!(events[2].outcome, Outcome::Cancelled);
        assert_eq!(
            recorder.reserve("ik-a", "model-unknown").err(),
            Some(Unrecorded::UnknownModel)
        );
    }

    #[test]
    fn a_request_of_no_tokens_is_not_reported() {
        let (recorder, metrics) = recorder(16);
        drop(recorder.reserve("ik-a", "model-a").unwrap());
        assert!(recorder.batch(10).is_none());
        assert!(
            metrics
                .render_prometheus()
                .contains("gateway_usage_events_pending{env=\"staging\"} 0")
        );
    }

    #[test]
    fn acknowledge_removes_only_the_sent_events() {
        let (recorder, _) = recorder(16);
        complete(&recorder, "ik-a", 1);
        complete(&recorder, "ik-a", 2);
        let (last, events) = recorder.batch(1).unwrap();
        assert_eq!(events.len(), 1);
        complete(&recorder, "ik-a", 3);
        recorder.acknowledge(last);
        let (_, left) = recorder.batch(10).unwrap();
        assert_eq!(
            left.iter()
                .map(|event| event.input_tokens)
                .collect::<Vec<_>>(),
            [2, 3]
        );
    }

    #[test]
    fn a_full_spool_refuses_new_requests_and_keeps_every_event() {
        let (recorder, metrics) = recorder(2);
        complete(&recorder, "ik-a", 1);
        // A request in flight holds a place too.
        let in_flight = recorder.reserve("ik-a", "model-a").unwrap();
        assert_eq!(
            recorder.reserve("ik-a", "model-a").err(),
            Some(Unrecorded::Full)
        );
        drop(in_flight);
        // It used no tokens, so it gave its place back.
        complete(&recorder, "ik-a", 2);
        assert_eq!(
            recorder.reserve("ik-a", "model-a").err(),
            Some(Unrecorded::Full)
        );
        let (last, events) = recorder.batch(10).unwrap();
        assert_eq!(events.len(), 2);
        recorder.acknowledge(last);
        assert!(recorder.reserve("ik-a", "model-a").is_ok());
        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains("gateway_usage_backlog_full_total{env=\"staging\"} 2"),
            "{rendered}"
        );
    }

    #[test]
    fn an_event_holds_no_content_or_credential_fields() {
        let (recorder, _) = recorder(16);
        complete(&recorder, "ik-a", 1);
        let (_, events) = recorder.batch(1).unwrap();
        let value = serde_json::to_value(&events[0]).unwrap();
        let mut fields: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
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
                "startedAt",
            ]
        );
    }
}
