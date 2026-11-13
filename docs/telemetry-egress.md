# Telemetry egress

This document lists all the telemetry that leaves a Confidential Inference
cluster. For each destination, it gives each field, the reason for the field,
and the retention if we know it.

Terms:

- **OTLP**: OpenTelemetry Protocol. The protocol that sends logs and spans
  to the collector.
- **Collector**: the stock OpenTelemetry Collector pod `telemetry-collector`.
  It is the only pod of the chart with an exit for telemetry. Its full
  configuration is one argument, and the allowlist pins that argument.
- **Relay**: the host `telemetry.relay.serverName`, at the fixed address
  `telemetry.relay.address`. The collector sends all telemetry to this host
  over TLS (Transport Layer Security).
- **Pseudonym**: a keyed hash (HMAC-SHA256, Hash-based Message
  Authentication Code with SHA-256) of an identifier. Only a holder of the key
  can link the pseudonym to the identifier.
- **GDPR**: the EU General Data Protection Regulation.

## 1. Rules

1. No request body or response body leaves the cluster. This includes
   prompts, completions, tool arguments, error texts that quote a request,
   and panic messages.
2. No client address leaves the cluster. This includes the TCP (Transmission
   Control Protocol) peer address, `X-Forwarded-For`, `X-Real-IP`, and
   `Forwarded`.
3. No HTTP header leaves the cluster. This includes `Authorization`, the
   caller `x-request-id`, and `User-Agent`.
4. A gateway log record names an API key only by its pseudonym. Section 3
   gives the reason that metrics keep the key record ID.

Under GDPR, a key record ID, a pseudonym, a timestamp, and an IP address are
personal data, also without content. Thus each field below has a reason.

## 2. How the rules are enforced

The senders write only reviewed records. The collector is a second gate. It
does not trust the senders.

| Layer | Control | Source |
|---|---|---|
| Gateway | Each log message is fixed text. A test fails when a message is not on the collector list. | `services/gateway/src/log_privacy.rs`, `services/gateway/tests/log_privacy.rs` |
| Gateway | `RUST_LOG` cannot open the debug output of the HTTP libraries (hyper, h2, axum, tower, reqwest, rustls). These libraries log only at `warn` and `error`. No HTTP library event goes to OTLP. | `log_privacy::log_filter`, `main.rs` |
| Gateway | The panic hook logs the code location. It does not log the panic message. | `log_privacy::install_panic_hook` |
| Gateway | The gateway does not read, log, or forward the body of a non-success upstream answer. The caller gets the status code and a fixed error body. | `lib.rs`, `upstream_error` |
| Gateway | An invalid request gets a fixed error code. The error does not quote the request. | `lib.rs`, `client_error` |
| Gateway | The audit record holds a key pseudonym, not the key record ID. | `TracingAuditSink`, `KeyPseudonyms` |
| Gateway | The client address is used in memory for rate limits only. No log, metric, or event holds it. | `protection.rs` |
| Maintenance gateway | The same HTTP library filter and panic hook. It sends no telemetry. | `services/maintenance-gateway/src/main.rs` |
| Collector | Removes all log attributes, scope attributes, and resource attributes except `service.name`. | `transform/logs` |
| Collector | Replaces a log body that is not text. | `transform/logs` |
| Collector | Replaces a gateway log body that is not a listed message or the exact audit record. If a statement fails, the body is replaced. | `transform/logs` |
| Collector | Replaces Bearer tokens and IPv4 and IPv6 addresses in all log bodies. | `transform/logs` |
| Collector | Cuts log times to whole seconds. | `transform/logs` |
| Collector | Keeps only the listed metric labels (Prometheus `labelkeep` and `keep_keys`). | `telemetry.labels` in `values.yaml` |
| Collector | Sends spans only as span metrics. Span attributes and span event attributes are removed first. | `transform/traces` |
| Tests | Run the real collector with the rendered configuration and check the output. | `tests/telemetry/test_collector.py`, `tests/helm/test_render.py` |

## 3. Destinations

The collector has two exporters and no others. The gateway has one more
exit, to the admin service. The maintenance gateway has no exit.

### 3.1 Metrics to the relay (Prometheus remote write)

- **Sender**: the collector, `prometheusremotewrite` exporter.
- **Destination**: `https://<relay>/prometheus/dataCollectionRules/<DCR>/streams/Microsoft-PrometheusMetrics/api/v1/write`.
  DCR is the Azure Monitor Data Collection Rule. The relay passes the samples
  to Azure Monitor managed Prometheus.
- **Authentication**: Microsoft Entra OAuth 2.0 client credentials, through
  the relay.
- **Interval**: one sample for each series each 15 s (`scrapeInterval`).

| Field | Example | Reason |
|---|---|---|
| Metric name | `gateway_requests` | The metric contract (`docs/observability-metrics.yaml`). |
| Value and sample time | `3`, scrape time | Counts and latencies for operations and alerts. |
| `environment`, `cluster`, `env` | `production` | Select the deployment. |
| `job`, `component`, `replica` | `gateway` | Select the workload. |
| `instance` | `10.52.1.7:9090` | The address of the scraped pod in the cluster. It is a server address, not a client address. It tells two replicas apart. |
| `model` | `deepseek-ai/...` | Usage and latency for each model. |
| `key_id` | `key_fa83...` | The opaque record ID of an API key (no name, no email). The admin console shows each customer the metrics of its own keys, and the deploy checks read one key's counter. See the open item below. |
| `status`, `reason`, `type`, `cache_status`, `event`, `router`, `le`, `quantile` | `200`, `stop` | Fixed values from the gateway code. |
| Router, worker, GPU, collector, and kube-state-metrics labels | `tp_rank`, `gpu` | The lists in `telemetry.labels`. They name code paths, ranks, GPUs, workers in the cluster, and Kubernetes objects. They hold no client address and no request data. |
| Span metrics | `traces.span.metrics.duration` | SGLang latency histograms. Labels: `service.name`, span name, span kind, and status code. |

Open item: `key_id` is kept as is. To use a pseudonym in metrics, the admin
console must compute the same pseudonym for the keys of a customer.

### 3.2 Logs to the relay (OTLP/HTTP)

- **Sender**: the collector, `otlphttp/loki` exporter.
- **Destination**: `https://<relay>/otlp/v1/logs`. The relay passes the logs
  to Loki.
- **Authentication**: HTTP basic authentication, user `telemetry.logs.username`.
- **Log senders in the cluster**: the gateway, and in PD (prefill and decode)
  mode the SGLang router and the inference pairs. Other pods send no logs.

Fields of each record:

| Field | Example | Reason |
|---|---|---|
| `service.name` | `gateway` | Tells the senders apart. |
| `deployment.environment`, `service.namespace` | `production`, `production-20260926` | Select the deployment. Set by the collector. |
| Time and observed time | `2026-11-13T10:00:01Z` | Order the events of an incident. Cut to whole seconds. |
| Severity | `INFO` | Filter errors. |
| Body | see below | The event. |

Gateway bodies. The collector lets only these leave:

- One of the fixed messages in `telemetry-collector.yaml`, for example
  `the key snapshot pull failed`.
- The audit record, one for each request:

  ```json
  {"event":"gateway_request_completed","key_ref":"kp_0123456789abcdef01234567",
   "request_id":"c0ffee00-cafe-4000-8000-deadbeef0002","route":"/v1/chat/completions","status":400}
  ```

| Audit field | Reason |
|---|---|
| `event` | Fixed text. |
| `route` | One of three fixed routes. Error rates for each route. |
| `status` | The HTTP status code that the caller got. |
| `request_id` | A UUID (Universally Unique Identifier) that the gateway makes for each request. The caller gets it in `x-ci-request-id`. A customer can give it to support, and support can find the record. It is never the caller's own `x-request-id`. |
| `key_ref` | The pseudonym of the API key record: `kp_` and the first 96 bits of HMAC-SHA256. The key is derived from the API key pepper, a secret of each environment that only the gateway and the admin hold. It lets support find the requests of one key. A log reader without the pepper cannot find the key. `null` for routes without a key. |

Router and pair bodies are fixed JSON diagnostic records. The writers check
each record against a schema before it is sent
(`images/sglang-router/private_router.py`, `images/sglang/pair_supervisor.py`).
Fields: `event`, `role`, `status`, `code`, counters such as `rank` and
`duration_ms`, `timestamp`, `run_id` (random for each run), `source_revision`,
and for stack frames a code `location`. They hold no request data.

### 3.3 Usage events and key snapshots to the admin service

- **Sender**: the gateway, directly. It is not telemetry, but it leaves the
  cluster, so it is listed here.
- **Destination**: `GATEWAY_ADMIN_ENDPOINT` (`gateway.admin.url`), over TLS
  with a bearer token from the CDS (Confidential Data Service) secret
  `product-usage`.
- **Data in**: the API key snapshot (key record IDs and peppered key hashes).
- **Data out** (only with `gateway.usage.enabled`): one event for each
  inference request.

| Field | Reason |
|---|---|
| `request_id` | A new random UUID for each event. The admin stores each event once. |
| `key_id` | Billing for each API key. |
| `requested_model` | Billing for each model. |
| `outcome` | `completed`, `failed`, `cancelled`, or `interrupted`. Billing and support. |
| `input_tokens`, `output_tokens`, `cached_input_tokens`, `reasoning_tokens`, `final_usage` | Billing. |
| `ended_at_ms` | Billing period. Millisecond time is needed to order and bill the events. |
| `producer_instance` | A random name for each gateway process. Deduplication. |

## 4. What does not leave

- Request bodies, response bodies, and upstream error texts.
- Prompts, completions, tool calls, and model output.
- HTTP headers, API keys, and the caller `x-request-id`.
- Client IP addresses and forwarding headers.
- Kubernetes pod addresses of clients. The collector adds no Kubernetes
  attributes and keeps no OTLP client metadata.
- Span attributes and span events (SGLang request IDs and stop strings).

## 5. Retention

The public repository does not set retention. These values come from the
private repository `confidential-inference-internal` on 2026-11-13:

| Store | Retention | Source |
|---|---|---|
| Loki on the admin VM | 7 days (`retention_period: 168h`) | `admin/infra/azure-vm/loki/loki.yaml` |
| Prometheus on the admin VM | 90 days | `admin/observability/scripts/start-prometheus-receiver.sh` |
| Azure Monitor managed Prometheus | Not set in the repositories. The Azure default is 18 months. | Azure documentation |
| Admin usage events | Not known | Admin database |

The relay configuration that maps `/otlp/v1/logs` and `/prometheus/...` to
these stores is not in either repository. Thus we cannot confirm from the
repositories which store receives the data of each deployment.

## 6. Timestamps

Operations need timestamps to order the events of an incident and to compute
rates. The collector cuts log times to whole seconds. Metric samples keep the
scrape time. A scrape each 15 s does not show the time of one request. Usage
events keep millisecond time for billing.

## 7. Change rules

- A new gateway log message must be added to the list in
  `telemetry-collector.yaml`. Else the collector replaces it. The test
  `every_gateway_log_message_is_on_the_collector_list` shows the missing
  message.
- A log message must be fixed text. Put values in fields. The collector
  removes all fields.
- A new metric label must be added to `telemetry.labels`, and this document
  must give its reason.
- Do not log a request, a response, a header, an error from `serde_json` on
  request data, or a value with `{:?}` that holds request data.
