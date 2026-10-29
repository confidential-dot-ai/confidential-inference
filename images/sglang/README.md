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

The image also contains the public `wait_for_model.py` and `fetch_model.py` repository files.
The gate waits for the late c8s mount and checks its read-only dm-verity source.
With `--plain-cache` the path is instead a read-only plain cache disk (public weights the
host can read); the byte check below is then the only integrity check, on every start.
`fetch-model fetch` fills that cache from Hugging Face before the worker starts. Its argv pins
the SHA-256 of the byte manifest; it downloads every file whose bytes differ and deletes every
file the manifest does not list. `fetch-model manifest` prints the byte manifest of a revision.
The gate also checks the model revision, metadata digests, model index, and weight shard presence.
The gate then hashes every file on the volume against the byte manifest. The release pins the
manifest's SHA-256 with `--expected-file`. A missing, extra, resized, or changed file fails the gate.
The gate fails closed before SGLang starts.
Each worker starts NVIDIA's dcgm-exporter after the model mount passes.
The image copies the binary and the DCGM libraries from the official
`nvcr.io/nvidia/k8s/dcgm-exporter` image at the digest in `source.lock`.
The exporter runs DCGM embedded in its own process (no separate host engine).
It sees only the GPUs granted to that worker. `dcgm-counters.csv` is NVIDIA's
`default-counters.csv` with the error, ECC, NVLink error, clock event and
confidential-compute fields enabled. It exports no request data.
`harden_http.py` runs at build time, on this image's source and on the
`sglang-dsv41` source. It removes every SGLang HTTP route that is not
inference, health, model or server info, or load reporting: cache flush,
weight updates, profiling, LoRA, sessions, memory release, logging, the
elastic EP router and the env-gated `/dumper` route. No flag, environment
variable or API key restores them. `/server_info` returns only the fields
the router reads. `launch_server` refuses the Rust, gRPC, Ray and encoder
frontends and the dumper listener, which have their own routes. The script
checks the SHA-256 of both source files and fails the build when the source
changes, so a new SGLang version needs a new review of its routes.

The image also defines no role command.
Kubernetes supplies the worker command and arguments at launch time.
The router has a separate image and digest under
[images/sglang-router](../sglang-router/README.md).

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

The simulator accepts `--reasoning-parser` and `--tool-call-parser` for command
compatibility. It removes both options before SGLang parses the arguments.
They do not change simulator output. Production still passes these options to
the normal SGLang server and keeps the normal parser behavior.

The small `sglang-simulator-replay-only.patch` delays imports for optional simulator
predictors. Replay mode does not need those packages. The patch does not change SGLang's
production module or Python environment.

## Build and smoke test

Run these commands from the repository root:

```sh
./images/sglang/build.sh
docker run --rm confidential-inference/sglang:local python3 -m sglang.launch_server --help
```

Set `IMAGE_NAME` to select a different local image name.
Local builds are for development tests. A production-ready candidate must
use the approved build and signed release pipeline. Local test results do
not authorize publication of a locally built release image.

The image is large. Build it on a machine with at least 40 GiB of free Docker storage.
This repository has no automated Blackwell correctness or performance test.
After deploy, send a real prompt through the deployed worker inside a TDX inference CVM.
Confirm that the response is correct.

## Release publication

Use the approved `Release images` workflow on public `main`. Publication
requires two clean builds with equal Linux AMD64 platform digests. SGLang
is built again for publication and must produce the same verified digest.
The signed release binds the selected image publication evidence.
See [release publication](../../release/README.md) for inputs and checks.

Do not replace the read-only build mounts with `COPY`. Git does not store file
modification times. A `COPY` layer would make the digest depend on the machine
that checked out the files.
