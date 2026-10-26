# SGLang DeepSeek-V4.1 image (draft)

This is a draft recipe for the worker image of the chart's prefill/decode
layout (`inference.pd`). The same image runs the prefill workers, the decode
workers and the Engram holder. The router runs from `images/sglang-router`.

It is not a release image: no release build has produced it, and
`scripts/affected-release-images.py` does not list it. `source.lock` says
`draft`, and `tests/images/sglang-dsv41` fails if someone registers the image
before that changes. Do not build it for a candidate.

## Inputs

Every input is pinned in `source.lock` and mirrored in a Dockerfile label.
`tests/images/sglang-dsv41` fails when the two differ.

| Input | Pin |
| --- | --- |
| Base image | `docker.io/nvidia/cuda:13.0.3-devel-ubuntu24.04`, linux/amd64 manifest digest (the index digest is recorded too) |
| uv | `ghcr.io/astral-sh/uv:0.11.16`, linux/amd64 manifest digest |
| Ubuntu packages | One `snapshot.ubuntu.com` timestamp. The base image's NVIDIA apt source is not read |
| Python environment | `requirements.lock`: 212 exact versions, each with the SHA-256 of every file PyPI publishes for it, installed with `--no-deps --require-hashes` |
| SGLang source | One commit of the public `confidential-dot-ai/Sglang-public` fork, with no patches. `source.branch` names the branch that holds it; `source.upstream` records the upstream SGLang commit the fork is based on |
| Model gate | `images/sglang/wait_for_model.py`, the public worker image's gate |

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

Nothing here has been built yet. These need a quiet build host before the
image can be registered:

1. Build twice from clean builders with the release workflow's flags and
   compare digests. The likely sources of a difference are the apt layer
   (`/var/cache/debconf`, `/etc/ld.so.cache`) and the editable install's
   `sglang.egg-info`.
2. Compare `pip list` and `dpkg -l` of the new image with the tested image.
   The versions of `vcs-versioning` and of the Ubuntu packages were not
   recorded by the tested build.
3. Run the worker smoke and benchmark on GPUs with the new image.
4. Add a build job sized like the `sglang` job (large disk), then register
   the image in `scripts/affected-release-images.py`.

## Source

`images/sglang` applies a reviewed patch to an upstream SGLang release. This
image does not: it builds from one commit of the `confidential-dot-ai/Sglang-public`
fork, the commit that holds the tested image's code. The fork is upstream
`a7fd2e1` (2026-10-19) plus changes to 223 files (the DeepSeek-V4.1
serving path, its kernels and its launcher), too much to carry and review as
one patch. `fetch_source.py` refuses `source.patches`. To change the image,
commit to the fork, then update `source.commit` and the
`ai.confidential.sglang.revision` label together.

The fork is public, so the build needs no credentials and anyone can rebuild
the image and compare its digest with the allowlist, which ties the digest to
reviewable source.

The pinned commit is on `Deepseek-V41-release-ced-pp-hicache-fix`, the commit
the tested image was built from. Later commits on that branch change only the
router (`sgl-model-gateway`), which this image does not copy.
