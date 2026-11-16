# Request body limit for a 1M-token context

This document gives the request body limit for a deployment with a 1M-token
(1,048,576-token) context. It also shows each component that limits the
request body, and the steps to raise all of them.

Terms:

- MiB: mebibyte, 1,048,576 bytes.
- JSON: JavaScript Object Notation.
- C8s: the confidential Kubernetes platform that runs this framework.
- CVM: confidential virtual machine.

## Result

| Item | Value |
| --- | --- |
| Recommended `gateway.protection.maximumBodyBytes` for a 1M-token context | 33554432 (32 MiB) |
| Gateway ceiling (`MAXIMUM_BODY_BYTES_CEILING`) | 67108864 (64 MiB) |
| Chart default | 2097152 (2 MiB), not changed |
| Recommended `gateway.protection.bodyTimeoutSeconds` for 32 MiB | 60 |

## The limits in the request path

A request goes through these components in this order. The smallest limit
applies.

| Component | Limit | Where it is set |
| --- | --- | --- |
| C8s front door (router nginx) | 1 MiB by default | The worker launch file, `router.maxRequestBodyBytes` (`c8s worker new --router-max-request-body-bytes`). The cloud chart sets a fixed 1 MiB |
| Gateway | `gateway.protection.maximumBodyBytes`, 1024 to 67108864 | The chart. The gateway refuses to start outside this range |
| SGLang router | 512 MiB (`--max-payload-size` default) | Upstream default. The chart does not set it. No change is necessary |
| SGLang worker HTTP server | No body limit found | No change is necessary |

C8s v0.99.38 has these details (paths in the C8s repository):

- `internal/cmds/nodeservices/router.go:22-37`: the launch-file field and
  the 1 MiB default.
- `charts/lib/files/router-nginx/nginx.conf:365-370`: nginx includes the
  limit in the application location and streams the body.
- `charts/cloud/templates/router-helpers.tpl:25`: the cloud chart sets a
  fixed 1 MiB.
- `internal/routing/proxy.go:26`: the tunnel record limit is a fixed 8 MiB.

The launch commits the digest of the whole launch file. Thus a change to the
front-door limit needs a new launch file, a `node-images` decree, and a new
launch of the worker VM. C8s issue
[confidential-dot-ai/C8s#1777](https://github.com/confidential-dot-ai/C8s/issues/1777)
asks for a change without a relaunch, a limit for each route, a cloud chart
value, and a decision on the tunnel limit.

## Calculation

A token is not a fixed number of bytes. The body size depends on the text,
the language, and how the client writes JSON.

| Content | Bytes for each token | 1,048,576 tokens |
| --- | --- | --- |
| English text, ASCII | about 4 | about 4 MiB |
| Source code, with JSON escapes for quotes and new lines | about 4 to 5 | about 5 MiB |
| Chinese, Japanese, or Korean text as UTF-8 (3 bytes for each character), about 1.5 characters for each token | about 4.5 | about 4.5 MiB |
| The same text as JSON `\uXXXX` escapes (6 bytes for each character). Python `json.dumps` does this by default | about 9 | about 9 MiB |
| Design point: escaped non-ASCII text at 2 characters for each token, or emoji as surrogate pairs (12 bytes) at 1 token each | 12 | 12 MiB |

Then:

1. The design point is 1,048,576 x 12 bytes = 12 MiB.
2. Chat messages and tool definitions add JSON structure. The tokenizer can
   also use more characters for each token than the average. A margin of 2
   gives 24 MiB.
3. We round up to a power of two: 32 MiB (33,554,432 bytes).

Assumptions and limits of this number:

- A body that is not realistic text can have more bytes for each token (for
  example, long runs of characters that JSON must escape). The gateway
  rejects such a body with 413. This is the correct result.
- Images are not in the calculation. A base64 image uses 4 bytes for each 3
  bytes of image data, and it has few tokens for its size. A deployment that
  accepts images must calculate its own limit. The 64 MiB ceiling leaves
  room for this.
- SGLang counts the context in tokens after the body arrives. The body limit
  does not make the context limit larger.

## Memory

The C8s front door streams the body, so its memory does not increase.

The gateway reads the full body into memory, parses it as JSON, and sends
the body to the router. One budget, `gateway.protection.bodyMemoryBytes`,
bounds the memory of all bodies in progress together
(`services/gateway/src/request_body.rs`):

1. Before the read, a request reserves 4 x its `Content-Length` (4 x
   `maximumBodyBytes` when the length is not known). When the budget does
   not have this space, the request waits up to `queueTimeoutSeconds`, then
   gets 429 `body_memory_capacity` with `Retry-After: 1`.
2. After the read, the gateway counts the JSON items of the body and
   changes the reservation to the cost of the parse: 2 x the body, plus
   2 x the longest string with an escape, plus 96 bytes for each JSON item
   and 768 bytes for each object. It returns the excess, or takes the
   difference without a wait or gets 429. A body whose cost is more than
   the whole budget gets 413 `request_too_large`.
3. After the parse, the reservation is 1 x the body until the router sends
   the response headers. A non-streaming response sends its headers at the
   end, so this part stays for the whole request.

The budget must be at least 5 x `maximumBodyBytes` + 64 KiB, so that one
request of the largest body fits. The chart and the gateway refuse a
smaller budget.

Measured peak heap of one request through the gateway (a counting
allocator, the body in 64 KiB chunks with a `Content-Length`, the chat
route with a routing key):

| Body | Before this change | Now | Reserved after the read (cost) |
| --- | --- | --- | --- |
| 31 MiB of plain text in one message | 5.0 x | 2.0 x | 2.0 x |
| 29 MiB of source code (escapes `\n`, `\"`) | 4.5 x | 3.4 x | 3.8 x |
| 27 MiB of CJK text as `\uXXXX` escapes | 3.0 x | 2.1 x | 3.0 x |
| 31 MiB agent transcript (2 KiB tool results) | 3.2 x | 3.2 x | 4.5 x |
| 31 MiB of 80-byte chat messages | 8.2 x | 8.2 x | 13.5 x |
| 8 MiB array of `0` (not realistic) | 17 x | 17 x | 50 x |
| 8 MiB array of `{"a":"b"}` (not realistic) | 68 x | 68 x | 108 x |

The gateway no longer copies the first user message to make the routing
key, and it drops the read body before it writes the changed body. The
reservation is at least the measured peak for each body in the table.

Size the gateway memory as:

    gateway.resources.memory >= 256 MiB + bodyMemoryBytes

`docs/long-context-sizing.md` gives the budget for a number of concurrent
large requests.

## Time

`bodyTimeoutSeconds` (default 10, maximum 60) is the time to receive the
full body. A 32 MiB body in 10 seconds needs about 27 Mbit/s from the
client. Set `bodyTimeoutSeconds: 60` for a 1M-token context. At 60 seconds
the client needs about 4.5 Mbit/s.

The prefill of a 1M-token prompt and the wait in the worker queue come
before the first token. Three gateway timeouts apply after the gateway sends
the body:

| Value | Default | Maximum | Applies to |
| --- | --- | --- | --- |
| `upstreamTimeoutSeconds` | 14400 | 86400 | The whole request, its stream included |
| `firstTokenTimeoutSeconds` | 3600 | 14400 | The first chunk of the response body after the router's headers |
| `streamIdleTimeoutSeconds` | 60 | 300 | Each later chunk |

`router.requestTimeoutSeconds` (default 14460) must be at least
`upstreamTimeoutSeconds`. In C8s v0.101.5 the front door nginx
(`proxy_read_timeout 3600s`) and the routing listener (`--backend-timeout`,
1 hour) end a request with no data for 1 hour. Thus the first token of a
streaming request, and all of a non-streaming request, must come within
1 hour, whatever the gateway values are.

## Steps for a 1M-token deployment

1. In the deployment values, set:

   ```yaml
   gateway:
     resources:
       memory: 9Gi
     protection:
       maximumBodyBytes: 33554432
       bodyTimeoutSeconds: 60
       # 64 large requests at the same time: 64 x 4 x 32 MiB.
       bodyMemoryBytes: 8589934592
   ```

   Also set the worker context length to 1,048,576 tokens, and size the
   concurrency from the GPUs (`docs/long-context-sizing.md`).
2. Write the worker launch file with
   `c8s worker new --router-max-request-body-bytes 33554432`. This needs a
   `node-images` decree and a new launch of the worker VM. Plan this with the
   operator. Until C8s#1777 is done, there is no other method.
3. Render the allowlist again. The gateway settings are environment, so the
   allowlist pins them.
4. Make sure that every value is set before you announce the context. In
   release v0.16.7 the chart value was 16 MiB, but the gateway ceiling was
   8 MiB. In v0.16.8 the gateway accepted 8 MiB, but the front door rejected
   bodies above 1 MiB.
5. Test with a body just below each limit and a body just above it. Expect
   200 and 413.
