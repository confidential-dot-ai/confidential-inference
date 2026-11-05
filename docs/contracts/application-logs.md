# Application log contract, version 1

This contract covers Confidential Inference gateway, maintenance gateway,
router, worker, and application telemetry collector output. C8s logs and
controls belong to the C8s team. This change does not change them.

## Record format

The source is `images/sglang-router/safe_events.json`. Each event has a fixed
component, an allowed field list, and required fields. Each field has a type
and a finite value list, numeric bounds, or a restricted code-identity format.
Unknown events, fields, versions, nulls, and wrong types are rejected. A record
must fit in 4,096 UTF-8 bytes. Run `scripts/sync-safe-events.py` after a contract
change. CI checks that the Rust and chart copies match the source exactly.

A gateway example is:

```json
{"schema_version":1,"component":"gateway","event":"gateway_response_started","route":"/v1/chat/completions","status":503}
```

No event accepts request or response content, prompts, completions, tool data,
headers, credentials, customer IDs, API key IDs or hashes, client IPs, caller
request IDs, raw URLs, exception text, environment dumps, or local values.
Route names are fixed API paths. They do not include query strings.

Worker run IDs come from the supervisor's random generator. Source revisions
come from the image build. Code locations must pass the installed code
catalogue in the worker supervisor as well as the contract's path format.
Do not obtain these fields from requests or exception messages. A matching
format alone does not establish safe provenance. Numeric fields must come
from the reviewed counter, timing, or status source for that event.

Timestamps, counts, run IDs, and deployment identity are operational metadata.
This contract does not assert that these records are anonymous or settle
personal-data classification. Product usage records, account records,
metrics, and trace-to-metric processing have separate purposes and controls.

## Existing producer migration

| Existing output | Version 1 replacement |
| --- | --- |
| Gateway request audit with key and request IDs | `gateway_response_started`, with fixed route and status only |
| Gateway configuration and listener text | Configuration, ready, listener-failure, drain, and shutdown event codes |
| Registry snapshots and pepper fingerprints | Snapshot counts and fixed refusal classes; no fingerprints |
| Usage queue and delivery messages | Fixed queue, rejection, retry-reason, and shutdown events |
| Raw dependency tracing, span fields, formatter output | No general tracing formatter or bridge; only validated application records enter sinks |
| Gateway startup errors and panics | Fixed startup-failure or panic records; no error chain, arguments, or panic payload |
| PD router reviewed error events | Same error classes under the shared versioned envelope |
| Router startup, exit, and unapproved records | Fixed lifecycle events and rejected-record counts |
| Worker watchdog, GPU, NCCL, scheduler, and code-location diagnostics | Existing safe diagnostic fields under the shared versioned envelope |
| Legacy worker and model-fetch process output | Contract validation at the process boundary; fixed start, exit, failure, and dropped-output events |
| Maintenance gateway readiness and failure | Fixed maintenance events |
| Collector's native text diagnostics | Output disabled; use collector health and metrics for delivery, rejection, queue, and export status |

`gateway_response_started` records the response decision. It does not assert
that a response stream finished. It replaces the misleading completion name.
The change preserves the API request-ID response header and product usage
identity. Those values are no longer diagnostic log fields.

Python and native child output stays in bounded, transient pipes before
validation. It is not copied to pod logs, files, delivery queues, or exports.
Unapproved legacy text is dropped. This removes details that have no approved
event equivalent; operators use lifecycle events, reviewed PD diagnostics,
health checks, and metrics. Adding those details again requires a reviewed
source event. Do not add a raw debug fallback.

Both stdout and OTLP queues are bounded. A blocked gateway stdout writer drops
records without blocking inference or OTLP. Its process counters appear in
`gateway_log_records_discarded_total`, with fixed reason labels. Python sink
queues count failed delivery and drops; their fixed delivery events report
those counts on shutdown. A full container stdout pipe can lose its local
summary too. These are best-effort diagnostic paths, not durable audit stores.

## Collector boundary

The chart derives validation from the same contract. The processor parses
bounded string bodies, validates each event and field, rejects unknown data,
and rebuilds the exported body before batching or export queues. A failed
parse is dropped. Structured OTLP bodies are not accepted as an alternative
input format. Only a JSON string containing an approved record is accepted.

The collector clears input log attributes, resource attributes, scope fields,
schema URLs, severity text, event names, flags, and trace/span IDs. The output
uses service name `confidential-inference`, scope `ci.safe.v1`, and fixed INFO
severity. The body contains the approved component and event. Existing pinned
environment and namespace identity are added after validation. Metadata from
an input producer cannot replace them. OTTL decodes JSON numbers as doubles;
validation permits only integral numeric values within the approved bounds.

Collector self logs are directed to `/dev/null`, including logging errors.
This prevents native exporter and transformation diagnostics from printing
records or a remote error response. Keep health checks and its metrics
endpoint enabled. Monitor filtered records, receiver refusals, exporter
failures, and queue drops. Do not enable collector debug output in a serving
cluster. The exporter still receives only validated records if its sink fails.

## API errors

The gateway returns fixed error codes for unsuccessful upstream HTTP responses.
It preserves status codes and bounded numeric Retry-After values. It does not
forward backend bodies or arbitrary backend headers. The existing controlled
503 response remains in use. Standard JSON and SSE error objects in a 2xx
response are replaced with a fixed error object. Transport and parser failures
close the body with a fixed error. Successful content, tool calls, model
rewriting, and usage extraction retain their existing contracts.

## Checks and release gate

Run the gateway and maintenance Rust suites and Clippy; the worker and router
image suites; the Helm tests; `tests/logging`; and `tests/telemetry`.
`tests/logging` tests every event against the real pinned collector image,
unknown records, secret markers, metadata removal, sink rejection, and timeout.
It also checks raw child exceptions, Python formatter failures, queue pressure,
signal forwarding, stdout failure, and contract-copy equality. CI runs these
suites for every PR. Only synthetic records may enter the fixtures.

Local tests do not establish live GPU behavior, deployed image identity,
capacity, or end-to-end delivery to the target store. Use the linked internal
acceptance runbook before the next deployment. Build all changed application
images through the approved release pipeline. A collector-first rollout drops
legacy records until producers are upgraded. A producer-first rollout leaves
the old collector's weaker export gate in place. Use an isolated candidate to
test the whole release first and record the expected logging gap during any
staged rollout. Reverting to the prior release also reopens its logging gaps.
