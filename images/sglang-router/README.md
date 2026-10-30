# SGLang Router image

This image contains the router at the exact upstream source in `source.lock`:
upstream SGLang `a7fd2e1` (2026-10-19), the commit the DeepSeek-V4.1 worker
source (`images/sglang`) is based on. Every deployment uses this one
router, in regular mode for the aggregated workers and in prefill/decode mode
for `inference.pd`. The build applies four patches, in the order
`source.lock` lists them; each later patch is a diff on the tree the earlier
ones produce:

1. `worker-withdrawal.patch` adds worker withdrawal, active-stream counts, a
   discovery fence, and drain status. It keeps upstream discovery and model
   routing. It also supports model aliases that map a public name onto
   backend groups. Withdrawal and model routes act on the regular router only:
   the prefill/decode router answers their endpoints but does not consult
   them when it picks workers.
2. `admission-caps.patch` adds request admission limits. See
   [Admission limits](#admission-limits).
3. `pd-router.patch` changes only the prefill/decode router. See
   [Prefill/decode relay](#prefilldecode-relay).
4. `http-no-tokenizer.patch` registers no router tokenizer for an HTTP
   worker. Only the gRPC routers tokenize; for an HTTP worker the router
   would load the worker's model path, which is not in the router's
   filesystem, and so download the tokenizer from the Hugging Face Hub (the
   router has no egress). The router's own `/v1/tokenize` and
   `/v1/detokenize` then have no tokenizer; the gateway does not route them.

`tests/images/sglang-router` checks each patch against its `source.lock`
digest, the order the Dockerfile applies them in, and the image labels that
record the digests.

The image uses a pinned Python runtime. `requirements.lock` fixes every
Python dependency version and file hash. It has a separate image name and
digest. Updating it does not update inference workers or download model files.

For a local development build, supply `SOURCE_REVISION` and `SOURCE_DATE_EPOCH`
from the public repository commit. Use an immutable digest for image tests.
The candidate router rehearsal must pass before this image is ready for use.

The upstream build-time field uses `SOURCE_DATE_EPOCH`, the fixed timestamp
of the public source commit. A missing or invalid timestamp stops the build.
The build sorts wheel archive entries without changing file contents, RECORD,
permissions, or source timestamps. Installation skips Python bytecode
compilation; Python can compile it at runtime. The release still requires two
clean builds with equal complete image digests. Archive sorting does not
permit different binaries or dependency contents.

Set `--enable-igw` explicitly for model-aware routing. Without this flag,
upstream regular mode ignores the request's model when it selects a worker.
In IGW mode, add workers through discovery or `POST /workers`; do not rely
on `--worker-urls` to populate the registry.

Run the built-image test before a candidate update:

```sh
ROUTER_TEST_IMAGE=<image-at-immutable-digest> \
  python3 -m unittest discover -s tests -p test_router_image.py
```

If the Docker daemon uses a different temporary directory, set
`ROUTER_TEST_TMPDIR` to a directory shared by the test process and daemon.

The test runs a local router and two fake HTTP workers. It checks model
selection, withdrawal, an open stream's drain count, registration fencing,
and recovery. It does not replace the candidate live rehearsal.

## Model routes

Set `CI_ROUTER_MODEL_ROUTES` to the routes JSON. It is environment, so the
exact c8s allowlist pins it; a route change changes the pod and rolls the
router. The router reads it once at start and rejects an invalid document.
Without it, aliases are absent.

```json
{
  "schemaVersion": 1,
  "routes": {"public-model": ["backend-old", "backend-new"]}
}
```

A public model name can select workers from several backend model groups.
The router sends the selected worker's backend model name in the upstream
request. After its first admission, retries stay in that selected backend
group. `GET /model-routes` on the private worker control API returns the
routes.

The routes contain model names only: no worker address, token, model
download credential, or encryption key.

The built-image test checks mixed groups, request model rewriting, and an
open stream across a worker drain. These local checks do not replace the
candidate worker/model rehearsal.

## Development publication

The local publication command below is only for isolated development tests.
Do not deploy its output to production or to a candidate prepared for production.
For those deployments, use the approved `Release images` workflow and signed
release pipeline. See [release publication](../../release/README.md).

For a reviewed development build that has passed the image test, publish
with a Docker registry login in tmpfs:

```sh
python3 images/sglang-router/publish.py --image <local-image> \
  --receipt /protected/path/router-publication.json
```

The script checks the image platform, source label, and build inputs. It records
publication time and the repository digest. This is a development artifact.
It does not provide the approved pipeline's build and publication evidence.

A production-ready candidate uses approved release artifacts and still needs
the router rehearsal and deployment checks.

## Admission limits

`admission-caps.patch` adds these `launch_router` flags. Each is off by
default, so a router started without them behaves as before. The chart's
aggregated router command sets none of them.

| Flag | Effect |
| --- | --- |
| `--reject-video` | A chat request with a video part gets 400 (`video_not_supported`, `param` names the message). |
| `--max-images-per-request N` | A chat request with more than N image parts gets 400 (`images_per_request_exceeded`). |
| `--max-inflight-images N` | A chat request whose images would raise the images in flight above N gets 429 (`image_capacity_exceeded`) with `Retry-After: 2`. |
| `--max-inflight-megapixels MP` | The same ceiling on image area in flight. The router reads width and height from the image header, not a decode. |
| `--unmeasured-image-megapixels MP` | The area charged to an image whose size the router cannot read, such as a remote URL. 0 uses the built-in default. |

Image slots are held until the response body ends or the client goes away,
so a streaming response counts for its whole lifetime. The limits apply to
`/v1/chat/completions` only: the pinned `openai-protocol` 1.0.0 drops every
non-text `/v1/responses` part, so that endpoint carries no images to count.

The patch also changes `--max-concurrent-requests N`. Without
`--rate-limit-tokens-per-second`, N is now a concurrency ceiling: a permit
returns only when its response body ends. Upstream refilled N permits per
second, so the limit never bounded concurrency. A refusal is a 429 with a JSON
error body and `Retry-After: 5`; a queue timeout is a 429, not a 408. A
request cancelled before its response returns its permit.

The private admin routes gain `GET /admission` and `POST /admission`
(`{"max_concurrent": N}`), which read and change the live concurrency ceiling.
Lowering it does not abort requests in flight. A router started without
`--max-concurrent-requests` reports `enabled: false` and answers the POST
with 503. The ceiling set this way is runtime state: it is not in the
release allowlist, and a restart returns to the rendered flag.

New metrics: `smg_admission_limit`, `smg_admission_inflight`,
`smg_admission_rejected_total{reason}`, `smg_image_limit`,
`smg_image_inflight`, `smg_image_pixels_limit`, `smg_image_pixels_inflight`
and `smg_image_rejected_total{endpoint}`. Their labels are in the telemetry
router label list.

## Prefill/decode relay

`pd-router.patch` changes `src/routers/http/pd_router.rs` and adds its
reliability tests. The regular router is unchanged.

- A streaming request without logprobs is relayed to the client as soon as
  decode answers with a 2xx, instead of after prefill's response. Decode
  sends its headers only with its first token, after prefill's KV has
  arrived, while prefill's response trails the KV transfer by a prefill
  scheduler iteration; the first token now skips that wait. Prefill keeps
  being driven in the background, and its failure ends the client stream.
- When decode rejects a request outright, the router returns that rejection
  at once and drops the prefill request, so prefill aborts it instead of
  waiting for a decode handshake until its bootstrap timeout.
- A 4xx from either worker is the client's fault and does not count against
  that worker's circuit breaker. When decode fails first and prefill is
  cancelled, prefill is not charged either.
