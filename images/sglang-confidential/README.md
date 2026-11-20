# SGLang image

This image pins official upstream SGLang commit
`a7fd2e1158c389c33077bae67fb797efa8dd09bd`. It does not use the custom
Sglang-public fork. The source lock records the exact source, CUDA base,
Python wheels, simulator, and GPU metrics exporter.

The plain V4.1 deployment runs a complete worker with four GPUs. The router
selects between two independent workers. Each worker runs in its own CVM.
Speculative decoding and prefill/decode disaggregation are disabled in that
deployment. It does not use a separate Engram holder, custom CPU staging,
CED handoff, HiCache, or custom rank-progress hooks.

The upstream source already contains the asynchronous device-to-host CC
copy worker. The deployment selects the multicast-free FlashInfer all-reduce
backend explicitly. Normal upstream model kernels remain enabled. Published
checkpoint precision is preserved; the build does not requantize weights.

The HTTP policy removes non-serving routes, OpenAPI, and documentation
routes. It also makes the worker refuse to start with a setting that logs or
dumps request data: request logging (`--log-requests`, `--log-requests-target`),
crash dumps, per-request metric files, tensor and msProbe dumps, forward hooks,
and speculative trace files (`REFUSED_SERVER_ARGS`). No deployment value can
turn these on. The model gate verifies the pinned repository, revision, metadata,
and model bytes before it starts the worker. These are serving and trust
controls, not changes to inference computation.

The media policy (`harden_media.py`) accepts request images, video and audio
only as inline data: bytes, a `data:` URL or raw base64. A URL, a `file://`
URL or a path returns a 400 error before any network or file access. Images
decode only as JPEG, PNG, WEBP or GIF. Audio and video reach FFmpeg only
when they start with a WAV, AVI, MP4/MOV, Matroska/WebM, FLAC, Ogg, MP3/AAC
or AMR header and contain no playlist or manifest marker, so FFmpeg never
selects a demuxer that follows nested URLs or files. FFmpeg still parses the
allowlisted containers in-process: torchcodec offers no forced demuxer or
protocol allowlist. The Transformers backend refuses video input. The upstream `--allowed-media-domains` and
`--media-url-max-file-size-mb` flags have no effect in this image, so the
launcher does not refuse them.

The listener policy (`harden_dist.py`) keeps the worker's internal
listeners on loopback for single-node runs:

- The `torch.distributed` store binds `127.0.0.1`, and the distributed
  init address is `127.0.0.1` whatever `--host`, `--dist-init-addr` or
  `SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE` say.
- The worker sets `GLOO_SOCKET_IFNAME=lo`, `NCCL_SOCKET_IFNAME=lo` and
  `NCCL_RAS_ENABLE=0`, and removes `NCCL_COMM_ID`, overriding the pod
  environment.
- The local IP that SGLang components bind or advertise is `127.0.0.1`,
  whatever `SGLANG_HOST_IP` or `HOST_IP` say. Data-parallel port
  reservations bind `127.0.0.1`.
- The prefill/decode KV bootstrap server binds `127.0.0.1`. Prefill
  registers with it and decode reaches it on `127.0.0.1` whatever `--host`
  or the request's `bootstrap_host` say. Every chart layout runs prefill and
  decode in one pod, so the bootstrap port in the chart's Service and
  container ports is no longer reachable from outside the pod.
- The launcher refuses multi-node runs, `--dist-init-addr`,
  `SGLANG_DISTRIBUTED_INIT_METHOD_OVERRIDE`, `--gated-launch-port`, elastic
  EP, the NIXL all-to-all backend, weight cache daemons, transfer-engine
  weight seeding, `--kv-events-config` and
  `--forward-pass-metrics-ipc-name`. Each of these opens another
  rendezvous, control or publisher listener.

`harden_dist.py` still accepts the old diagnostic fork source
(`diagnostic-fork`), which only the removed GPU-test image built.

Server output is always private. `wait-for-model` reads the SGLang stdout
and stderr through a pipe, in memory only. It never writes that output to
stdout, stderr or disk, because prompts, responses and exception messages
can appear in it. It writes only fixed JSON events to its own stdout, one
object per line, at most 4096 bytes, with no free text:

| Event | Keys |
| --- | --- |
| `worker_ready` | `model_revision`, `gpus`, `load_seconds` (first `GET /health` = 200) |
| `request_failed` | `error_class`, `http_status`, `phase`, `input_tokens_bucket`, `duration_ms` (always null), `exception`, `location` |
| `gpu_oom` | `location` |
| `cuda_error` | `code`, `location` |
| `nccl_error` | `code`, `location` |
| `worker_error` | `error_class`, `exception`, `location` |
| `worker_exit` | `exit_code`, `signal` |
| `jit_compile` | `cache`, `files` (a kernel compiled after `worker_ready`) |

Every event also has the `event` key. `exception` is the exception type name
only; the message is always discarded. `location` is the last SGLang
traceback frame, for example `sglang/srt/managers/scheduler.py:1234`.
`error_class`, `phase`, `code` and `input_tokens_bucket` come from fixed
lists. The node log agent keeps only these events and keys. A request
traceback that no failed response line claims within 5 seconds is reported
as `worker_error`. The supervisor also writes `worker_exit` with exit code 1
when it stops before the server starts (model check failure or timeout).
The model-mount progress and rejection messages stay on stderr; they contain
no request data.

`jit_compile` reports a kernel that a compiler built at run time. Such a
compile blocks the SGLang scheduler. On 2026-11-19 a 67-second FlashInfer
sampling compile on the first top-k/top-p request let the liveness probe
kill both staging workers. A compiled kernel is also not part of the
measured image. After `worker_ready`, every 5 seconds, the supervisor lists
the cache directories of each compiler in the image: FlashInfer, Triton,
torch inductor, DeepGEMM, the SGLang JIT kernels, the CUDA driver PTX cache,
TileLang, CuTe DSL, TVM-FFI, and any other file below `~/.cache`. It compares
file names and sizes, and reads no content. Files that exist at
`worker_ready` (startup compiles) are not reported. `cache` is one of
`flashinfer`, `triton`, `inductor`, `deep_gemm`, `sglang_jit`, `cuda`,
`tilelang`, `cute_dsl`, `tvm_ffi` and `other`; `files` is the number of new
or changed files in one scan. The event holds no path or file name. The
directories, and the source that sets each one, are listed in
`wait_for_model.py`.

`--private-server-output` is still accepted, but it does nothing: the output
is always private. Native CUDA and application error text is not available
in any log; only the event fields above are. Metrics remain separate. The image contains the same pinned NVIDIA DCGM
exporter used by the older worker. Its compatibility must be tested in the
confidential GPU VM. Metrics labels are restricted by the telemetry collector.

The CPU simulator remains outside the production Python import path. It is
used only by the simulator staging profile (`inference.mode: simulator`).

This is the one engine image. It holds no model. A worker gets its model
files at start from a model server (`inference.model.download`) or from an
attached C8s model volume (`inference.model.c8sVolumeSource`); the chart
selects the model with values only. Every model, for example the Qwen3.5-0.8B
staging recipe (`tests/fixtures/deployments/qwen35-staging-values.yaml`), runs
on this image.

Build and publication use the existing Image Preparation workflow, including
its independent rebuild audit. Deploy only published images with verified
pipeline evidence and a signed release. A local build is not a candidate
release image.
