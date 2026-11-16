# Load test plan for 1M-token requests

Status: Plan. No tool for this test exists yet.

This plan has two tests:

1. **Staging transport test.** It sends `N` concurrent requests of about
   32 MiB through the real path of a staging deployment. It shows that no
   component before the GPUs refuses or loses a request of the largest size.
2. **Candidate gate.** It sends real 1M-token requests to the candidate
   deployment. It shows that the GPUs serve them, and it measures the
   values of `docs/long-context-sizing.md`.

Terms: `N` is the number of concurrent requests (default 64). "The real
path" is client, TEErminator, the C8s front door, the routing listener, the
mesh, the gateway, the SGLang router and the worker. Do not send the test to
the router or a worker directly.

## Preconditions

Do these before each test. Each one has caused a refusal in an earlier
deployment (`docs/request-body-limit.md`).

- The worker launch file sets
  `c8s worker new --router-max-request-body-bytes 33554432`. Check the
  front door: a body of 33554432 bytes must not get 413 from nginx.
- The deployment values set the values of `docs/long-context-sizing.md` for
  `N`: `maximumBodyBytes`, `bodyMemoryBytes`, `bodyTimeoutSeconds`,
  `inferenceConcurrency`, `perKeyConcurrency`, the gateway and router
  memory, and `router.requestTimeoutSeconds`.
- The test API key has no `rateLimit` and no `tokenBudget`, or limits larger
  than the test uses.
- The client sends `Content-Length`, streams the body, and has no read
  timeout below `firstTokenTimeoutSeconds`.

## Test 1: staging transport test

### Requests

Each request is a streaming chat completion (`"stream": true`) of about
32 MiB, just below `maximumBodyBytes`. The prompt of a real 1M-token
request is larger than the staging model's context (Qwen3.5-0.8B: 262,144
tokens), so the worker would refuse it. Thus put the bulk of the body in a
field that the router drops:

```json
{"model": "Qwen/Qwen3.5-0.8B", "stream": true, "max_tokens": 64,
 "messages": [{"role": "user", "content": "<about 1 KiB of text>"}],
 "padding": "<about 32 MiB of text: ASCII, with JSON escapes>"}
```

The gateway, the front door and the routing listener read, count and send
all of the body. The router parses all of it and drops `padding`. The
worker gets only the messages. Use three body shapes: plain text, source
code (many `\n` and `\"` escapes) and JSON `\uXXXX` escapes. The gateway
reserves a different share of its budget for each shape.

Run a second pass with the bulk in the message content, at the model's
context length (about 1 MiB for 262,144 tokens of English text). This pass
sends the prompt text through the router's `cache_aware` tree and the
worker's prefill.

### Steps

1. Send one request of each shape. Expect 200 and a complete stream (the
   last event is `data: [DONE]`).
2. Send `N` requests at the same time, from one client address and one API
   key. Repeat three times.
3. Send `N + 8` requests at the same time. Expect 429
   `inference_capacity` or `body_memory_capacity` for the requests above
   the capacity, with `Retry-After`, and 200 for the others. No other
   status.
4. Send one body of `maximumBodyBytes + 1` bytes. Expect 413
   `request_too_large` from the gateway, not from nginx (the gateway error
   body is JSON with `"code": "request_too_large"`).

### Pass criteria

- Every request of steps 1 and 2 gets 200 and a complete stream.
- No request gets 413, 408, 429 or 5xx in steps 1 and 2, and no stream ends
  early (a stream that ends without `[DONE]` is a failure).
- No pod restarts, and no pod has an OOM kill
  (`kube_pod_container_status_last_terminated_reason`, the node log).
- The peak memory of the gateway is less than `256 MiB + bodyMemoryBytes`.
  Record the peak memory of the gateway and the router for each shape.
- The gateway counter `gateway_rejections` with `reason="body_memory_capacity"`
  or `reason="inference_capacity"` does not increase in steps 1 and 2.
- The router metric `smg_admission_rejected_total` does not increase.

Record: the time to the first chunk (p50, p95, maximum), the total time,
the upload time of the body, and the memory of the gateway and the router
over time.

## Test 2: candidate gate for real 1M-token requests

Run this on the candidate deployment, with the production model and GPUs,
before the `production` alias moves.

### Requests

Streaming chat completions with a prompt of 1,000,000 to 1,048,576 tokens
less `max_tokens`. Count the tokens with the model's tokenizer before you
send. Use different prompts, so that the prefix cache does not hide the
prefill time. Use English text, source code and CJK text.

### Steps

1. Send one request. Record `P` (the time to the first token) and `D`.
   Check that the response `usage.prompt_tokens` is the counted number.
2. Send `C = W x R` requests at the same time (all run on the GPUs).
3. Send `N` requests at the same time (`N - C` wait in the worker queue).
4. Send one request of 1,048,577 tokens plus `max_tokens`. Expect 400 from
   the worker (`invalid_request`), not a refusal before the worker.

### Pass criteria

- Every request of steps 1 to 3 gets 200, a complete stream and the counted
  `usage.prompt_tokens`.
- The longest time to the first token in step 3 is less than
  `firstTokenTimeoutSeconds` and less than 3600 s (the C8s front door).
- The longest total time is less than `upstreamTimeoutSeconds`.
- No worker leaves the router's set of healthy workers during the test
  (the router logs and the `/health` checks). A long prefill can delay the
  worker's `/health` answer; three failed checks of 5 s remove the worker.
- No pod restarts and no OOM kill. The memory of the gateway and the router
  stays in the values of `docs/long-context-sizing.md`.

Record `P`, `D`, `R` (`max_total_num_tokens` in the worker start log) and
the measured memory. Write them in the deployment values and in
`docs/long-context-sizing.md` when they change the sizing.

## Open items

- C8s: the 1 h idle limit of the front door and the routing listener is
  fixed in C8s v0.101.5. A first token after more than 1 h needs a C8s
  change.
- The sealed tunnel accepts at most 8 MiB for each request. A tunnel client
  cannot send a 1M-token request.
