# SGLang image

This recipe starts from the official SGLang v0.5.18 Linux AMD64 image.
It applies one public, hash-pinned patch with two reviewed confidential-compute fixes.
It also adds the model-mount gate.
It does not rebuild CUDA, FlashInfer, or the remaining Python stack.

The `source.lock` file records the official image digest, upstream source commit,
FlashInfer version, patch digest, and source commits for both fixes.
The Dockerfile repeats both values so that a reviewer can inspect the recipe without running a tool.
The focused tests stop the build when these values differ.

The first fix moves blocking device-to-host result copies to a host worker thread.
The second fix selects a multicast-free FlashInfer all-reduce path under confidential compute.
The worker also selects the canonical CUDA runtime and verifies that it exports
`cudaDeviceReset`. It does not select TileLang's limited CUDA stub.
FlashInfer 0.6.17 already contains the merged global-timer and multicast-free workspace fixes.

The image also contains the public `wait_for_model.py` and `gpu_metrics.py` repository files.
The gate waits for the late c8s mount and checks its read-only dm-verity source.
The gate also checks the model revision, metadata digests, model index, and weight shard presence.
The gate fails closed before SGLang starts.
Each worker starts one local GPU metrics endpoint after the model mount passes.
The endpoint reads only the four GPUs assigned to that worker. It exports use, memory,
temperature, and ECC counters. It does not export GPU identifiers or request data.
The image also defines no role command.
Kubernetes supplies the router or worker argument list from `source.lock` at launch time.

## GPU-free staging mode

The same image contains the SGLang simulator from upstream pull request 33824.
The source is pinned to one commit in `source.lock`.
It is stored under `/opt/confidential-inference/sglang-simulator`.
It is not present on the normal Python import path.

Production uses `python3 -m sglang.launch_server` and the real model volume.
Staging sets `inference.mode=simulator` in Helm.
This starts the SGLang HTTP server, scheduler, cache, streaming path, and metrics on CPU.
Only the GPU model execution is simulated.
The server returns deterministic `prefix` text and does not load model weights.

One exception: when a chat completion request carries `tools` and the prompt
asks for one of them, or `tool_choice` names one, the simulator answers with
a fixed, OpenAI-shaped `tool_calls` entry instead of prefix text. The function
name comes from the first tool. The arguments echo that tool's first required
parameter with a fixed value. `finish_reason` is `tool_calls`, in both
streaming and non-streaming responses. Every other request keeps the existing
prefix-text path unchanged. The `sglang-simulator-tool-calls.patch` adds this
path; it does not touch SGLang's production module.

The small `sglang-simulator-replay-only.patch` delays imports for optional simulator
predictors. Replay mode does not need those packages. The patch does not change SGLang's
production module or Python environment.

One exception: when a chat completion request sets `chat_template_kwargs.thinking: true`
and the worker was launched with `--reasoning-parser=deepseek-v4`, the simulator answers
with `<think>{reasoning text}</think>{answer text}` instead of the usual fixed text. SGLang's
real, unmodified DeepSeekV4Detector reasoning parser then splits that text into
`reasoning_content` and `content` exactly as it would for a real model's output, in both
streaming and non-streaming responses. Every other request keeps the existing text path
unchanged. The `sglang-simulator-reasoning.patch` adds this path; it does not touch
SGLang's production module and composes with `sglang-simulator-tool-calls.patch` (PR #56)
once that lands, since the two patches touch different layers -- token generation here,
`OpenAIServingChat.handle_request` there.

## Build and smoke test

Run these commands from the repository root:

```sh
./images/sglang/build.sh
docker run --rm confidential-inference/sglang:local python3 -m sglang.launch_server --help
docker run --rm confidential-inference/sglang:local python3 -m sglang_router.launch_router --help
```

Set `IMAGE_NAME` to select a different local image name.
Do not publish this local image until the full release checks pass.

The image is large. Build it on a machine with at least 40 GiB of free Docker storage.
This repository has no automated Blackwell correctness or performance test.
After deploy, send a real prompt through the deployed worker inside a TDX inference CVM.
Confirm that the response is correct.

## Audit the published digest

The local build above is for development. Normal release builds and publishes
the image once. After the release set is final, run
`scripts/rebuild-release-images.py`. It rebuilds this image from the source
commit in the release bundle and compares the Linux AMD64 platform digest.

Do not replace the read-only build mounts with `COPY`. Git does not store file modification
times. A `COPY` layer would make the digest depend on the machine that checked out the files.
