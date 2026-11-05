# SGLang DeepSeek-V4.1 image

This is the release recipe for the worker image of the chart's prefill/decode
layout (`inference.pd`). The same image runs the prefill workers, the decode
workers and the Engram holder. The router runs from `images/sglang-router`.

The approved release workflow builds this image twice on separate runners,
compares the digests, then requires the publication build to match. Local
builds are test evidence only. Candidate GPU tests use the published image.

## Inputs

Every input is pinned in `source.lock` and mirrored in a Dockerfile label.
`tests/images/sglang` fails when the two differ.

| Input | Pin |
| --- | --- |
| Base image | `docker.io/nvidia/cuda:13.0.3-devel-ubuntu24.04`, linux/amd64 manifest digest (the index digest is recorded too) |
| uv | `ghcr.io/astral-sh/uv:0.11.16`, linux/amd64 manifest digest |
| Ubuntu packages | One `snapshot.ubuntu.com` timestamp. The base image's NVIDIA apt source is not read |
| Python environment | `requirements.lock`: 212 exact versions, each with the SHA-256 of every file PyPI publishes for it, installed with `--no-deps --require-hashes` |
| SGLang source | One commit of the public `confidential-dot-ai/Sglang-public` fork, with no patches. `source.branch` names the branch that holds it; `source.upstream` records the upstream SGLang commit the fork is based on |
| Model gate | `images/sglang/wait_for_model.py`, the public worker image's gate |
| HTTP policy | `images/sglang/harden_http.py --variant pd`, shared with the public worker image (see its README) |

The base is the CUDA devel image because FlashInfer, Triton and the SGLang JIT
kernels compile at run time. The image bakes no JIT cache: compiled kernels
are machine-specific build outputs and would make the image depend on the
build host's GPU. The chart gives the pod an emptyDir for them instead, so a
pod compiles them once per start.

## Reproducible build

The release workflow builds a candidate twice, from clean builders, and
publishes only when both image digests are equal. This recipe is written for
that check:

- `SOURCE_DATE_EPOCH` is the source commit time, and the exporter rewrites
  file timestamps (`rewrite-timestamp=true`).
- No apt list, cache, or log stays in a layer. No BuildKit cache mount is
  used. uv runs without a cache.
- No bytecode is written at build time or at run time.
- The Python environment's files get mtime 0, as in the tested image.
- The source stage removes `.git`. setuptools-scm gets a fixed version
  (`0.0.0.dev0`, the version of the tested image), not one derived from tags.

Two builds from clean builders differed in these files, which the recipe
now removes or fixes:

- `/var/cache/fontconfig/*.cache-9`, written by the fontconfig trigger in the
  apt layer: removed with the apt lists.
- `sglang-0.0.0.dev0.dist-info/uv_cache.json`, which holds the build-time
  ctime of `pyproject.toml` (uv's reinstall check), and `RECORD`, which hashes
  it: the install deletes the file and its `RECORD` line.
- `__pycache__/__editable___sglang_0_0_0_dev0_finder.cpython-312.pyc`, written
  by the final import check (`python -I` ignores `PYTHONDONTWRITEBYTECODE`):
  the check runs with `-B`.
- `site-packages/build_backend.py`, the PEP 517 build shim that both
  `flashinfer-python` and `torch-c-dlpack-ext` ship; uv installs wheels in
  parallel, so either copy can win. Nothing imports it at run time: the
  install deletes it and its `RECORD` line in both packages.

The image selector tracks this recipe and its shared model gate and HTTP
hardening inputs. The release workflow gives each clean worker build its
own runner and disk cleanup. GPU acceptance remains a deployment gate.

## Source

The worker builds from one pinned commit of the public
`confidential-dot-ai/Sglang-public` fork. It replaces the prior worker recipe
in `images/sglang`; git history keeps that recipe. The worker package remains
`ghcr.io/confidential-dot-ai/confidential-inference/sglang`.

The fork is public, so the build needs no credentials and anyone can rebuild
the image and compare its digest with the allowlist, which ties the digest to
reviewable source.

The pinned commit is on `fix/worker-recovery-20261104`. It adds scheduler
progress records, numeric failure events and fixed process exit deadlines
to the previously deployed source. The GPU tests used these same worker
source files. The approved image pipeline builds the pinned commit.

## CPU staging

The same image includes the existing pinned CPU simulator and its reviewed
patches. Staging selects it with `PYTHONPATH`; production does not. The
simulator does not require a second worker package. Run its startup and
completion checks on the published image before signing a release.

The simulator adapter uses `Req.prefix_len` and `Req.extend_len` from the pinned SGLang source.
The old `prefix_indices` field no longer exists. The pinned prefix-length
patch changes only simulator accounting; it does not patch the worker.

Run the CPU staging checks on the published worker image:

```sh
python3 tests/images/sglang/smoke.py ghcr.io/confidential-dot-ai/confidential-inference/sglang@sha256:<digest>
```

The check starts an isolated CPU container with no network access. It requires
startup, model discovery, and streaming and nonstreaming completion responses.
It saves the results and container log. It does not contact a cluster.

## Paired worker development

The optional `inference.pd.paired` chart settings render two independent pods.
Each pod has one application container for its prefill/decode pair, model
verification and the resident Engram holder. C8s adds its support containers separately. Pod-wide
process sharing stays disabled. The router pins each prefill URL to the decode
URL in the same pod through `CI_ROUTER_PD_PAIRS`.

`pair_supervisor.py` divides the container's assigned GPU UUIDs between the two
workers. It starts prefill before decode. It requires every expected rank,
worker startup health and frontend availability. A failed worker stops the
pair. Shutdown sends SIGTERM, then SIGKILL to both process groups after the
configured grace period. The next container start uses a fresh progress
record directory.

The fork publishes scheduler progress from the scheduler thread. GPU completion
events distinguish submitted work from completed work. Idle schedulers publish
progress too. `/livez`, `/readyz` and `/startupz` read cached state and return
an empty response. They perform no model request or CUDA operation. The C8s
five-second probe limit stays unchanged. Failed startup and liveness probes
have a separate kill deadline: the supervisor shutdown limit plus 15 seconds
(45 seconds by default). The normal pod shutdown grace period stays separate.

Worker stdout and stderr go to `/dev/null`. Only fixed error events with
reviewed numeric fields reach container logs through a local datagram socket.
Request logging, raw tracing and dump files are disabled in this profile.
CUDA and NCCL wrappers export numeric failure codes. Metrics remain on each
worker's existing HTTP port. On a detected pair failure, the supervisor requests
a bounded snapshot from all registered ranks. It exports only these fields:

- Rank progress: role, rank, reason code, CPU progress age and pending GPU age.
- Scheduler: stage code, batch size, token counts and step time.
- Python stacks: installed code file label, line number and frame order. No
  function name, local value, source text, thread address or unknown file path.
- PyTorch NCCL recorder: reviewed collective type, state, group number, sequence,
  element/byte counts and available CPU discovery times. No tensor values,
  process-group names, raw stack text or native dump file.
- Watchdog: firing, communicator abort start/finish/failure, forced exit deadline
  and process exit code. CUDA/NCCL wrappers use numeric error codes.

The parent adds a random worker-run ID and the image source revision. This run
ID identifies a process lifetime; it is not a request ID. Each record goes to
container stdout and, when telemetry is enabled, the internal OTLP collector.
The sender has a bounded queue, retry count and shutdown wait. It does not read
credentials, proxy settings, tracing baggage or request objects.

The recorder stores 256 entries per process group in memory. A snapshot exports
at most 32 reviewed entries and 128 code frames per rank. Capture has a short
deadline. Unavailable snapshots and delivery failures have fixed error events.
The health handler remains independent of capture and delivery.

This path cannot identify every stalled GPU kernel. PyTorch recorder coverage
does not include all direct CUDA, PyNccl or Mooncake operations. A stopped or
exited rank may not answer a snapshot request. Generated code paths are omitted.
Native per-connection KV queue/state events and end-to-end request-ID correlation
are not provided by this change. Existing aggregate KV transfer, queue and token
metrics remain available on the separate worker ports. Raw stack, recorder,
profiler, request and core dump files remain disabled.

The paired launch profile uses source field allowlists. It excludes prompt and
response text, tool content, tensor values, local variables, raw credentials,
client-supplied IDs and arbitrary exception messages. Sizes, timing and counts
are permitted. Non-secret key/account IDs may be used by the access layer; they
are not needed in worker error logs. This policy applies to the guarded paired
launch command. A direct library launch needs its own review.

Run the process and privacy acceptance checks on the isolated GPU test CVM:

```sh
python3 -m unittest discover -s tests/images/sglang -p test_pair_supervisor.py -v
```

The process tests use synthetic workers. They do not prove inference, GPU
assignment, CUDA IPC, NVLink, performance or C8s behavior. Those require the
real-model and published-release gates.

For a local GPU test image, use `Dockerfile.gpu-test` and a named
`sglang-source` build context that points to the exact fork checkout. Record
both source revisions and the resulting image digest. This image is for
isolated tests only. Production and production-ready candidates use the
approved release recipe, build audit and signed release pipeline.

### Transport acceptance

Test both transports on the GPU CVM. The container layout alone does not
prove that KV transfers use NVLink.

For paired pods, `inference.pd.paired.transport` selects `tcp` or `nvlink`.
The chart sets all required variables and removes conflicting overrides.
The chart default is TCP. The normal release selects NVLink after GPU validation.
A production change still needs the signed chart and
allowlist process. It is not an automatic runtime fallback.

- For local NVLink, set `MC_INTRANODE_NVLINK=1` and
  `SGLANG_MOONCAKE_CUSTOM_MEM_POOL=INTRA_NODE_NVLINK`. Unset `MC_FORCE_TCP`.
  The second setting puts transfer metadata on the GPU. Use legacy CUDA
  allocations; CUDA expandable segments cannot export legacy IPC handles.
- For TCP, set `MC_FORCE_TCP=1`. Unset both NVLink settings. The native
  library checks whether these variables exist, so do not use `0` to unset
  them. Keep `MOONCAKE_PROTOCOL=tcp` in the TCP profile.
- First check synthetic GPU transfers with the installed Mooncake package.
  Then check real SGLang requests, streaming, performance and pair recovery.

`tests/images/sglang/mooncake_integrity.py` checks the SGLang transfer wrapper
with synthetic GPU buffers. Run it inside the test image with four assigned
GPUs, once with `nvlink` and once with `tcp`. It checks both local GPU ranks,
single and batch transfers, nonzero allocation offsets, transfers from an
executor thread, and received byte equality. It does not load a model.

`tests/images/sglang/inference_check.py` sends synthetic requests to a ready
test router. It checks chat and text requests, streaming, token usage, timing,
and a private test value in the selected container logs. Reports contain
counts and timings. They do not contain prompts, outputs or credentials.
  Record the selected transport and transfer measurements. A ready endpoint
  or a visible NVLink connection does not prove that KV data used that path.

TCP is an explicit recovery configuration. Do not assume that an NVLink
transfer error causes a transparent switch to TCP. Verify the restart with
the TCP configuration separately. Keep raw buffers, addresses, handles and
native diagnostic output out of worker logs.


Diagnostic output is bounded. A full container stdout pipe drops complete
records instead of blocking the supervisor. The independent OTLP queue can
still export them. Neither path exports raw worker output. On failure, the
snapshot sender waits at most 20 ms per record and sends the newest reviewed
NCCL entries first. It reports successful sends and rejected entries. These
bounds also mean that an overloaded or damaged logging path can lose context.
Scheduler token counts use only the lengths of native token arrays; token
values never enter the record.

Both image recipes remove group and world write permissions from installed
SGLang source. The image build then checks that the stack catalog includes
the scheduler, Engram staging, GPU communicator, and NCCL code locations.
Missing critical locations fail the build. This keeps the code-location safety
filter strict and checks that it retains useful application frames.
