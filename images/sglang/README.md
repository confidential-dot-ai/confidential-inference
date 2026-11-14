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
routes. The model gate verifies the pinned repository, revision, metadata,
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

`Dockerfile.gpu-test` applies the listener policy too. It skips the media
policy, whose hash pins cover only the release source.

For the plain deployment, `--private-server-output` discards native server
stdout and stderr. It exports only a fixed worker-exit event with a numeric
code. This prevents request text and arbitrary exception text from entering
that log path. It also means native CUDA and application error details are
not available there. Report this diagnostic limit in the deployment receipt.
Metrics remain separate. The image contains the same pinned NVIDIA DCGM
exporter used by the older worker. Its compatibility must be tested in the
confidential GPU VM. Metrics labels are restricted by the telemetry collector.

The CPU simulator remains outside the production Python import path. It is
used only by the simulator staging profile (`inference.mode: simulator`).

The Qwen3.5-0.8B staging image (`images/sglang-qwen35`) builds the same
engine from the same inputs in this directory: `source.lock`,
`requirements.lock`, `fetch_source.py`, the `harden_*.py` build steps,
`wait_for_model.py`, `fetch_model.py` and `dcgm-counters.csv`. A change to one
of them rebuilds both images. When you add a build step here, add it to
`images/sglang-qwen35/Dockerfile` too; `tests/images/sglang/test_qwen35_recipe.py`
fails until both Dockerfiles match.

Build and publication use the existing Image Preparation workflow, including
its independent rebuild audit. Deploy only published images with verified
pipeline evidence and a signed release. A local build is not a candidate
release image.
