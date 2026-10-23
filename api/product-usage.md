# Product usage events

The gateway reports one usage event per request. It keeps no usage on disk. The admin stores the events and computes all totals.

## Event

One event describes one completed, failed, cancelled, or interrupted request. The gateway records it when the request ends.

| Field | Type | Meaning |
| --- | --- | --- |
| `request_id` | string | A fresh lowercase UUIDv4 per event. It is never the caller's `x-request-id`, so a caller cannot make two requests collide. |
| `key_id` | string | The registry key ID that authenticated the request. |
| `requested_model` | string | The model the caller requested. It must be a model of the usage configuration. |
| `outcome` | string | `completed`, `failed`, `cancelled`, or `interrupted`. |
| `final_usage` | boolean | The upstream sent its final usage report. |
| `input_tokens` | integer or null | Null when not observed. |
| `output_tokens` | integer or null | Null when not observed. |
| `cached_input_tokens` | integer or null | Part of `input_tokens`, never added again. |
| `reasoning_tokens` | integer or null | Part of `output_tokens`, never added again. |
| `ended_at_ms` | integer | Request end, Unix milliseconds. |
| `producer_instance` | string | `gateway-<uuid>`, new for each gateway process. |

The event has exactly these fields. Null means not observed; zero is a measured zero. The served model, model revision, producer, environment, cluster, and key realm are not event fields. The admin takes them from the token's binding.

## Delivery

The gateway keeps events in an in-memory queue of at most 100,000 events. When the queue is full, the gateway drops the oldest event, keeps serving, and counts the drop in `gateway_usage_events_dropped_total`.

Every five seconds the gateway sends the queue in batches of at most 500 events, one batch at a time: `POST <endpoint>` with `Authorization: Bearer <token>` and the body `{"events":[...]}`. Any 2xx response delivers the batch. On any other result the events stay queued, and the delay doubles up to 60 seconds. Redirects are disabled. TLS verifies the receiver. On shutdown, after the HTTP drain, the gateway sends the remaining events for up to 20 seconds.

Delivery is at least once. A batch may arrive more than once after a timeout or a lost response. The admin stores each `request_id` once, so a repeated event is not counted again. Events still queued when a gateway process ends without a flush are lost.

## Receiver

The admin authenticates the token and maps it to one binding: producer, environment, cluster, key realm, and approved models. A batch has at most 500 events and 262,144 bytes.

The admin drops and counts an invalid event: a missing or extra field, a `request_id` that is not a UUIDv4, an unknown requested model, a negative or non-integer token count, `cached_input_tokens` above `input_tokens`, `reasoning_tokens` above `output_tokens`, or an `ended_at_ms` more than five minutes in the future. Other events of the batch are stored.

A well-formed batch answers `200` with `{"received":N,"inserted":N,"rejected":N}`. `inserted` excludes events already stored. A missing or unknown token answers `401`. An oversized batch answers `413`. A malformed envelope answers `400`. A storage failure answers `503`, and the gateway retries.

## Totals

The admin computes totals from the stored events by minute of `ended_at_ms`, producer, key, and model. The request count equals the sum of outcome counts and the sum of usage completeness counts. A request has complete usage when `final_usage` is true and both input and output tokens are known, partial usage when it is not complete but input or output tokens are known, and unavailable usage when neither input nor output tokens are known. Known-token counts distinguish missing observations from measured zeros. Usage completeness is independent of outcome.

## Configuration

The CDS secret `/confidential-inference/gateway/product-usage` supplies `endpoint` (the HTTPS ingest URL), `token`, optional `tls_ca_pem` (when set, the only trusted CA), optional `connect_address`, and `models` (each requested model with its served model and model revision). The origin of `endpoint` also serves the key snapshot the gateway pulls (see `gateway-admin.openapi.json`). The secret is never a public ConfigMap or a Kubernetes Secret. No credential enters an event or an error log.

The gateway reports `gateway_usage_events_pending`, `gateway_usage_events_dropped_total`, and `gateway_usage_send_failed_total{reason}`.

## Accounting limits

Streaming usage is requested internally even when callers omit it. Injected final usage frames are removed when the caller did not request them. Collection handles split bytes and records final cumulative totals once. Disconnects, missing final usage, and router retries limit gateway-observed accounting. This interface does not claim complete accounting of all GPU work.

Prompts, response content, plaintext keys, arbitrary headers, caller metadata, and exception text are not permitted fields. Reports expose only approved usage fields and completeness, never registry verifier material.
