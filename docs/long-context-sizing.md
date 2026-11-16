# Size a deployment for 1M-token requests

This document tells you how to set each component before the GPUs, so that
the GPUs set the only limit for long requests. Size from the GPU capacity
first, then set every other value from it.

Terms:

- 1M tokens: 1,048,576 tokens.
- MiB, GiB: 1,048,576 and 1,073,741,824 bytes.
- KV cache: the GPU memory that holds the keys and values of the tokens of
  each running request.
- Prefill: the step in which the worker reads the whole prompt before the
  first output token.
- Body: the JSON of one request. `docs/request-body-limit.md` explains how
  to measure its size. Token count does not determine a fixed byte count.

## 1. The limits in the request path

A request goes through these components in this order.

| Component | Body | Time | Concurrency and memory |
| --- | --- | --- | --- |
| C8s front door nginx (C8s v0.101.5) | `router.maxRequestBodyBytes` of the worker launch file (`c8s worker new --router-max-request-body-bytes`), 1 MiB by default. It streams the body | 3600 s with no data from the routing listener (`proxy_read_timeout`), 3600 s to send (`proxy_send_timeout`), 60 s between two writes to the client (`send_timeout`) | No limit found |
| C8s routing listener (`cds-attest`, port 8802) | No limit. It streams the body | `--backend-timeout` 1 h with no data in either direction | No limit found |
| Gateway | `gateway.protection.maximumBodyBytes` (at most 64 MiB) | `bodyTimeoutSeconds` (60 at most) for the body; `firstTokenTimeoutSeconds`, `streamIdleTimeoutSeconds` and `upstreamTimeoutSeconds` for the response | `inferenceConcurrency`, `inferenceQueue`, `perKeyConcurrency`, `perAddressConcurrency`, `globalRequestConcurrency`, `bodyMemoryBytes`, `gateway.resources.memory` |
| SGLang router | 512 MiB (`--max-payload-size` default) | `router.requestTimeoutSeconds` (`--request-timeout-secs`), the whole request | `router.maxConcurrentRequests` (off by default), `router.resources.memory` |
| SGLang worker | No limit found | No limit found | `inference.maxRunningRequests`, the KV cache, `inference.contextLength` |

The C8s sealed tunnel (`/tunnel` on the front door) is a different path. It
accepts at most 8 MiB for each request record (`MaxTunnelRecordBytes`) and
buffers at most 32 MiB of each response. A client that uses the tunnel
cannot send a 1M-token request. The open C8s issue
[confidential-dot-ai/C8s#1777](https://github.com/confidential-dot-ai/C8s/issues/1777)
covers the front-door body limit.

## 2. The GPU capacity

For each worker, find:

- `R`: the requests that the worker runs at the same time
  (`--max-running-requests`). For 1M-token requests, the KV cache sets it:
  `R` is at most the KV cache tokens of the worker divided by 1,048,576.
  SGLang writes `max_total_num_tokens` in its start log.
- `P`: the prefill time of one 1M-token prompt, in seconds, measured on the
  hardware with `--chunked-prefill-size` 4096 (256 chunks for 1M tokens).
- `D`: the decode time of the longest output, in seconds.

With `W` workers, the GPUs run `C = W x R` requests at the same time. The
other requests wait in the worker queue.

Set the worker values:

```yaml
inference:
  # The model's own value when the model configuration has 1M tokens or
  # more; else 1048576 (the model must support it).
  contextLength: 1048576
  maxRunningRequests: <R>
```

Do not also put `--context-length` or `--max-running-requests` in
`inference.workerExtraArgs`. The chart refuses the duplicate.

## 3. Gateway concurrency

The gateway holds one inference slot for each request until its response
ends. Choose `N`, the number of long requests that the deployment accepts
at the same time. `N` is at least `C`. When `N` is more than `C`, the worker
queue holds `N - C` requests.

```yaml
gateway:
  protection:
    inferenceConcurrency: <N>
    inferenceQueue: 0
    # One client or key can use all of N, for a load test or a large tenant.
    perKeyConcurrency: <min(N, 128)>
    perAddressConcurrency: <N or more>
    globalRequestConcurrency: <N plus the expected short requests, at least>
```

`inferenceQueue` holds a request at the gateway for `queueTimeoutSeconds`
(30 s at most). A long request waits longer than that, so let the worker
queue hold it: increase `inferenceConcurrency`, not `inferenceQueue`.

The admin can also set a request rate and a token budget for each key
(`services/gateway/gateway/keys.py`). One 1M-token request counts more
than 1,048,576 tokens against the budget.

## 4. Gateway memory

The Python gateway has one main process and six parser processes. Size
memory from measured RSS for all seven processes. The shared body budget
also covers receive, inspection, and JSON object construction. See
[request-body-limit.md](request-body-limit.md) for its phases and errors.

```yaml
gateway:
  protection:
    maximumBodyBytes: 33554432
    bodyTimeoutSeconds: 60
    bodyMemoryBytes: <simultaneous receive and parse reservations plus headroom>
  resources:
    memory: <measured main and parser RSS plus headroom>
```

The old Rust heap measurements and its 4 x upload sizing rule do not size
the Python parser. Test representative text, escaped text, and structured
requests. `gateway.resources.memory` is a request, not a limit. The node
must also have memory for the router and other pods.

## 5. Router

```yaml
router:
  # At least gateway.protection.upstreamTimeoutSeconds. The chart refuses
  # a lower value.
  requestTimeoutSeconds: 14460
  # 0: the router admits every request. A value above 0 must be at least
  # W x R; the chart refuses a lower value.
  maxConcurrentRequests: 0
  resources:
    memory: <1Gi + N x 3 x maximumBodyBytes, see below>
```

The router parses each request into a typed request, copies the prompt text
for the `cache_aware` policy, and writes the body again for the worker:
about 3 x the body for each request until the worker sends the response
headers (for a non-streaming request, until the end). The `cache_aware`
radix tree also holds the prompt text. It evicts to `--max-tree-size`
(67,108,864 characters) only every 60 s (`--eviction-interval-secs`), so
between two evictions it can hold the text of every request in that time.
Measure the router memory in the load test
(`docs/plans/long-context-load-test.md`).

## 6. Time

| Value | Set it to | Default |
| --- | --- | --- |
| `gateway.protection.firstTokenTimeoutSeconds` | The longest queue wait plus `P`: `ceil((N - C) / C) x (P + D) + P`, with a margin. At most 3600 in effect: the C8s front door ends a request with no data for 1 h | 3600 |
| `gateway.protection.upstreamTimeoutSeconds` | `firstTokenTimeoutSeconds + D`, with a margin | 14400 |
| `gateway.protection.streamIdleTimeoutSeconds` | The longest gap between two output chunks under full load. The chunked prefill of other requests runs between the decode steps | 60 |
| `router.requestTimeoutSeconds` | `upstreamTimeoutSeconds` + 60 | 14460 |
| `gateway.shutdownGraceSeconds` | The upstream deadline plus body upload, both capacity waits, and measured parsing time, with a margin | 900 |
| `gateway.terminationGracePeriodSeconds` | Endpoint drain + shutdown grace + 20 s usage flush, with a margin | 960 |

The current 900-second shutdown grace does not cover a 14400-second
request. Override it for the long-request profile before testing a rolling
update. The example below sets shutdown grace to 14400 + 120 seconds.
Its container termination period also includes 35 seconds for endpoint
drain, 20 seconds for usage flush, and a 5-second margin. Measure the time
before forwarding under full load and increase the 120-second allowance
if needed. A long shutdown grace does not delay an idle gateway: it exits
when its admitted requests and cleanup finish.

A non-streaming request sends nothing until it ends, so it must end within
1 h (the C8s front door). Use streaming for long requests.

## 7. Example

Two workers (`W = 2`), each with KV cache for 12 requests of 1M tokens
(`R = 12`), so `C = 24`. The deployment accepts `N = 64` and `U = 64`:

```yaml
inference:
  contextLength: 1048576
  maxRunningRequests: 12
gateway:
  shutdownGraceSeconds: 14520
  terminationGracePeriodSeconds: 14580
  resources:
    memory: <measured main and parser RSS plus headroom>
  protection:
    maximumBodyBytes: 33554432
    bodyMemoryBytes: <measured reservation peak plus headroom>
    bodyTimeoutSeconds: 60
    inferenceConcurrency: 64
    perKeyConcurrency: 64
    firstTokenTimeoutSeconds: 3600
    upstreamTimeoutSeconds: 14400
router:
  requestTimeoutSeconds: 14460
  resources:
    memory: 8Gi
```

Also write the worker launch file with
`c8s worker new --router-max-request-body-bytes 33554432`
(`docs/request-body-limit.md`, step 2).
