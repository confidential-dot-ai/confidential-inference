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

For the plain deployment, `--private-server-output` discards native server
stdout and stderr. It exports only a fixed worker-exit event with a numeric
code. This prevents request text and arbitrary exception text from entering
that log path. It also means native CUDA and application error details are
not available there. Report this diagnostic limit in the deployment receipt.
Metrics remain separate. The image contains the same pinned NVIDIA DCGM
exporter used by the older worker. Its compatibility must be tested in the
confidential GPU VM. Metrics labels are restricted by the telemetry collector.

The CPU simulator remains outside the production Python import path. It is
used only by the staging profile. The local GPU-test Dockerfile belongs to
the earlier fork experiment and is not an input to this release.

Build and publication use the existing Image Preparation workflow, including
its independent rebuild audit. Deploy only published images with verified
pipeline evidence and a signed release. A local build is not a candidate
release image.
