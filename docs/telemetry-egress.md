# Telemetry egress

This document lists all the telemetry that leaves a Confidential Inference
cluster. For each destination, it gives each field, the reason for the field,
and the retention if we know it.

Terms:

- **OTLP**: OpenTelemetry Protocol. The protocol that sends logs, metrics
  and spans to the collector.
- **Collector**: the stock OpenTelemetry Collector pod `telemetry-collector`.
  It is the only pod of the chart with an exit for telemetry. Its full
  configuration is one argument, and the allowlist pins that argument.
- **Node log agent**: the DaemonSet `node-log-agent`, one pod on each node,
  of the same pinned collector image. It reads the container output that the
  kubelet writes under `/var/log/pods` (a read-only host mount) and sends
  only reviewed records to the collector over the C8s mesh. It has no exit,
  no secret, and no Kubernetes API access. Its configuration is one argument
  too.
- **Log policy**: `helm/confidential-inference/templates/_log-policy.tpl`.
  The list of the records and fields that may leave, for each source. The
  agent and the collector both apply it.
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

Each container writes JSON events to its standard output. The node log
agent keeps only the records of the log policy and drops the rest. The
collector is a second gate. It does not trust the agents or the senders.

The SGLang workers and the SGLang router do not write their own output.
Each runs under a supervisor that keeps the output in memory, never on
stdout or disk, and writes only fixed events (`wait-for-model` in
`images/sglang-confidential/wait_for_model.py`, the router launcher in
`images/sglang-router/private_router.py`).

| Layer | Control | Source |
|---|---|---|
| Gateway | Writes one JSON object per line to stdout. Each log message is fixed text. A test fails when a message is not on the log policy list. | `services/gateway/src/log_privacy.rs`, `services/gateway/tests/log_privacy.rs` |
| Gateway | `RUST_LOG` cannot open the debug output of the HTTP libraries (hyper, h2, axum, tower, reqwest, rustls). These libraries log only at `warn` and `error`. | `log_privacy::log_filter`, `main.rs` |
| Gateway | The panic hook logs the code location. It does not log the panic message. | `log_privacy::install_panic_hook` |
| Gateway | The gateway does not read, log, or forward the body of a non-success upstream answer. The caller gets the status code and a fixed error body. | `lib.rs`, `upstream_error` |
| Gateway | An invalid request gets a fixed error code. The error does not quote the request. | `lib.rs`, `client_error` |
| Gateway | The audit record holds a key pseudonym, not the key record ID. | `TracingAuditSink`, `KeyPseudonyms` |
| Gateway | The client address is used in memory for rate limits only. No log, metric, or event holds it. | `protection.rs` |
| Maintenance gateway | The same HTTP library filter and panic hook. It sends no telemetry. | `services/maintenance-gateway/src/main.rs` |
| Worker | `wait-for-model` keeps SGLang's output in memory and writes only `worker_ready`, `request_failed`, `gpu_oom`, `cuda_error`, `nccl_error`, `worker_error` and `worker_exit`. A traceback becomes the exception type and one SGLang code location; the message is dropped. An unknown error is `unclassified`. | `images/sglang-confidential/wait_for_model.py`, `tests/images/sglang-confidential/test_server_output.py` |
| Router | The launcher keeps the router's output in memory and writes only the reviewed events. | `images/sglang-router/private_router.py` |
| Node log agent | Reads `/var/log/pods` read-only. Takes namespace, pod and container from the file path. Keeps a record only when the log policy lists its source and event (or, for a C8s or collector source, its level and message). Keeps only the listed fields, checks each one against its pattern, and drops the others. A statement that fails does not log (`error_mode: silent`) and the record is dropped. | `templates/node-log-agent.yaml`, `transform/classify` |
| Node log agent | In a message of a text source, replaces Bearer tokens, `Authorization`, `User-Agent` and `X-Api-Key` values, and IPv4 and IPv6 addresses, and cuts it to 256 characters. | `transform/classify` |
| Node log agent | Counts every record it reads, kept or dropped, by source: `node_log_agent.records{source, kept}`. | `count` connector |
| Collector | Removes all log attributes, scope attributes, and resource attributes except `service.name` and the pod identity. | `transform/logs` |
| Collector | Replaces a body that is not a JSON object of a listed source with a listed event (or a text source's message), and removes the fields that the log policy does not list for that source. If a statement fails, the body is replaced. | `transform/logs` |
| Collector | Adds `environment`, `deployment` and `framework_release` to every body. | `transform/logs` |
| Collector | Replaces Bearer tokens and IPv4 and IPv6 addresses in all log bodies. | `transform/logs` |
| Collector | Cuts log times to whole seconds. | `transform/logs` |
| Collector | Keeps only the listed metric labels (Prometheus `labelkeep` and `keep_keys`). | `telemetry.labels` in `values.yaml` |
| Collector | Sends spans only as span metrics. Span attributes and span event attributes are removed first. | `transform/traces` |
| Tests | Run the real agent and collector with the rendered configuration on log files with a canary marker, a client address, a user agent and a Bearer token, and check the output. | `tests/telemetry/test_node_log_agent.py`, `tests/telemetry/test_collector.py`, `tests/helm/test_render.py` |

## 3. Destinations

The collector has two exporters and no others. The gateway has its own
exits, to Confidential Cloud. The maintenance gateway has no exit.

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
- **Log sources in the cluster**: every container writes to its stdout. The
  node log agent on each node reads them and keeps the records of these
  sources: `gateway`, `sglang-router`, `inference-worker`, `c8s` (the
  containers C8s injects into a pod, and the pods in `c8s-router` and
  `c8s-system`), `telemetry-collector` and `node-log-agent`. It drops the
  records of every other container (for example kube-system pods) and counts
  them.

Labels of each stream (Loki index labels):

| Label | Example | Reason |
|---|---|---|
| `service.name` | `inference-worker` | The source. |
| `deployment.environment` | `production` | The environment. |
| `k8s.cluster.name` | `production-fedcba987654` | The deployment (chart value `deployment`, which only `scripts/render-allowlist.py --deployment` sets). |
| `service.namespace` | `production` | `telemetry.deployment`, the `cluster` label of the metrics. |
| `k8s.namespace.name`, `k8s.pod.name`, `k8s.container.name` | `inference-worker-0-0` | The container. From the log file path. |

Fields of each record:

| Field | Example | Reason |
|---|---|---|
| Time and observed time | `2026-11-13T10:00:01Z` | Order the events of an incident. Cut to whole seconds. |
| Body | see below | The event, a JSON object. |

Each body holds the event fields of its source and these identity fields:
`service`, `namespace`, `pod`, `container`, `node` (the node name, from
`spec.nodeName`), `environment`, `deployment` and `framework_release`. Loki
keeps no structured metadata, so the identity is in the body too.

Gateway bodies. The log policy lets only these leave:

- One of the fixed messages of the log policy, as `{"event": "<message>",
  "level": "info"}`, for example `usage delivery delayed`.
- The audit record, one for each request:

  ```json
  {"event":"gateway_request_completed","key_ref":"kp_0123456789abcdef01234567",
   "request_id":"c0ffee00-cafe-4000-8000-deadbeef0002","route":"/v1/chat/completions","status":400}
  ```

| Audit field | Reason |
|---|---|
| `event` | Fixed text. |
| `route` | One of four fixed routes. Error rates for each route. |
| `status` | The HTTP status code that the caller got. |
| `request_id` | A UUID (Universally Unique Identifier) that the gateway makes for each request. The caller gets it in `x-ci-request-id`. A customer can give it to support, and support can find the record. It is never the caller's own `x-request-id`. |
| `key_ref` | The pseudonym of the API key record: `kp_` and the first 96 bits of HMAC-SHA256. The key is derived from the gateway's CDS secret, which only attested gateway pods hold. It lets support find the requests of one key, through a gateway that computes the pseudonym. A log reader without the secret cannot find the key. `null` for routes without a key. |

Router bodies: the fixed events of `images/sglang-router/README.md` with the
fields `event`, `role`, `status`, `code`, `timestamp` and `source_revision`.

Worker bodies (`images/sglang-confidential/README.md`):

| Event | Fields | Reason |
|---|---|---|
| `worker_ready` | `model_revision`, `gpus`, `load_seconds` | The worker serves, with the model revision and the start time. |
| `request_failed` | `error_class`, `http_status`, `phase`, `input_tokens_bucket`, `duration_ms`, `exception`, `location` | Error rates by class. `input_tokens_bucket` is a size class, not a count. `duration_ms` is null: SGLang's output does not give it. |
| `gpu_oom`, `cuda_error`, `nccl_error` | `code`, `location` | GPU faults by a fixed code. |
| `worker_error` | `error_class`, `exception`, `location` | An error that no request owns. Unknown errors are `unclassified`. |
| `worker_exit` | `exit_code`, `signal` | The server stopped. |

`exception` is a Python type name and `location` is a frame of SGLang code
(`sglang/<path>.py:<line>`). Both are checked against a pattern; neither can
hold a message.

C8s, collector and agent bodies: `level` and `msg`. These components do not
read request content. The agent replaces tokens, header values and addresses
in `msg` and cuts it to 256 characters.

### 3.2a Node log agent metrics (OTLP to the collector, then 3.1)

The agents send `node_log_agent.records{source, kept, node}` and their own
`otelcol_process_*` and export counters. The collector keeps only these
names and these labels.

### 3.3 Key checks and usage reports to Confidential Cloud

- **Sender**: the gateway, directly. It is not telemetry, but it leaves the
  cluster, so it is listed here.
- **Destinations**: `GATEWAY_CLOUD_ORIGIN` (`gateway.cloud.origin`) and
  `GATEWAY_USAGE_ORIGIN` (`gateway.usage.origin`), each over TLS to a pinned
  address that is also an allowlist exit.
- **Key checks**: `GET /inference/whoami` with the key a request presents as
  its bearer token, and nothing else. Only a string of an inference key's
  form is sent. Confidential Cloud answers the key's record ID, whether its
  org may be served, and when the key expires.
- **Usage reports** (only with `gateway.usage.enabled`):
  `POST /inference/usage`, with a TLS client certificate that carries the
  gateway's reporter key. One entry for each request that used tokens:

| Field | Reason |
|---|---|
| `id` | A new random UUID for each request. Confidential Cloud records each id once, so a report can be sent again. |
| `key` | The key's record ID, as whoami answered it. Billing for each key and org. |
| `model` | The requested model. Its price. |
| `location` | `gateway.usage.location`, the region the gateway serves. Its price. |
| `startedAt`, `finishedAt` | The billing hour. RFC 3339 times. |
| `inputTokens`, `cachedInputTokens`, `outputTokens` | Billing. Uncached input, cached input and output; the three never overlap. |

## 4. What does not leave

- Request bodies, response bodies, and upstream error texts.
- Prompts, completions, tool calls, and model output.
- HTTP headers, API keys, and the caller `x-request-id`.
- Client IP addresses and forwarding headers.
- Kubernetes pod addresses of clients. The collector and the agent add no
  Kubernetes attributes from the API and keep no OTLP client metadata.
- SGLang's own output: prompts in debug lines, exception messages, and
  access-log paths and client addresses.
- Span attributes and span events (SGLang request IDs and stop strings).

## 5. Retention

The public repository does not set retention. These values come from the
private repository `confidential-inference-internal` on 2026-11-13:

| Store | Retention | Source |
|---|---|---|
| Loki on the admin VM | 7 days (`retention_period: 168h`) | `admin/infra/azure-vm/loki/loki.yaml` |
| Prometheus on the admin VM | 90 days | `admin/observability/scripts/start-prometheus-receiver.sh` |
| Azure Monitor managed Prometheus | Not set in the repositories. The Azure default is 18 months. | Azure documentation |

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
  `templates/_log-policy.tpl`. Else the agent and the collector drop it. The
  gateway log privacy test shows the missing message.
- A log message must be fixed text. Put values in fields. The agent removes
  all gateway fields.
- A new worker or router event or field must be added to the log policy, to
  the writer's schema, and to this document.
- Staging and production use the same log policy. The pipelines of two
  deployments differ only in the identity labels (`tests/helm/test_render.py`).
- A new metric label must be added to `telemetry.labels`, and this document
  must give its reason.
- Do not log a request, a response, a header, an error from `serde_json` on
  request data, or a value with `{:?}` that holds request data.

## 8. Not yet covered

- The CDS VM: it is not a pod, so no agent reads its output.
- C8s services that are host units on a worker (the NRI admission plugin,
  the attestation API, the kubelet and containerd): they log to the journal,
  and the stock collector image has no `journalctl`. A refusal of an
  unlisted pod is in the NRI plugin's journal and the kubelet event, not in
  Loki. Follow-up: a journal reader for these units.
- kube-system pods (Cilium, CoreDNS, kube-proxy): dropped and counted as
  `unlisted`.
