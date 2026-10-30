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

The pinned commit is on `Deepseek-V41-release-ced-pp-hicache-fix`, the commit
the tested image was built from. Later commits on that branch change only the
router (`sgl-model-gateway`), which this image does not copy.

## CPU staging

The same image includes the existing pinned CPU simulator and its two reviewed
patches. Staging selects it with `PYTHONPATH`; production does not. The
simulator does not require a second worker package. Run its startup and
completion checks on the published image before signing a release.
