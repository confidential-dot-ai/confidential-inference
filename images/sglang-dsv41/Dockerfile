# DRAFT: the DeepSeek-V4.1 prefill/decode worker image (chart inference.pd).
# It is not a release image yet: no release build has produced it, and
# scripts/affected-release-images.py does not list it. README.md lists what
# has to happen first.
#
# Build context: the repository root (Dockerfile.dockerignore keeps only this
# recipe and images/sglang/wait_for_model.py). Every input is pinned: base
# images by linux/amd64 digest, Ubuntu packages by one snapshot timestamp,
# Python wheels by SHA-256, and the SGLang source by one commit of the
# Sglang-public fork (no patches: the other SGLang image patches upstream).
# The image bakes no JIT cache: FlashInfer, Triton and the SGLang JIT kernels
# compile at run time into the pod's emptyDir.

FROM ghcr.io/astral-sh/uv@sha256:265d074d08ed8080bc578087ca68a8e94611f9c7be671d40e18b3d3b1ad0dad4 AS uv

# The CUDA 13.0.3 toolkit the image was tested with. Kernels compile against it
# at run time, so this is the devel image.
FROM docker.io/nvidia/cuda@sha256:7d56ebe2b7cd864a60dca3c8b2d0a39f8fc110417e8253e32505c3387f59119c AS base
ENV DEBIAN_FRONTEND=noninteractive
# Ubuntu packages come from one snapshot.ubuntu.com timestamp (source.lock
# ubuntuSnapshot), never the moving archive. The base image's NVIDIA apt
# source is not read. Mooncake links ibverbs/mlx5, libnl, numa and curl even
# for intra-node NVLink; FFmpeg keeps torchcodec's import quiet; the OpenSSL
# headers serve the HiCache hash extension's JIT build; git serves the
# source stage.
RUN printf 'deb https://snapshot.ubuntu.com/ubuntu/20261020T000000Z %s main universe\n' \
        noble noble-updates noble-security > /tmp/snapshot.list \
    && apt-get -o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/dev/null \
        -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/dev/null \
        install -y --no-install-recommends \
        python3.12 python3.12-dev python3.12-venv \
        build-essential ca-certificates curl git procps libssl-dev \
        ibverbs-providers libibverbs1 libnuma1 libcurl4t64 libnl-3-200 libnl-route-3-200 \
        libavcodec60 libavdevice60 libavfilter9 libavformat60 libavutil58 libswresample4 libswscale7 \
    && rm -rf /tmp/snapshot.list /var/lib/apt/lists/* /var/cache/apt/*.bin /var/cache/apt/archives/*.deb \
        /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache

COPY --from=uv /uv /usr/local/bin/uv
# No bytecode at build or run time: a .pyc records its source's mtime, and the
# runtime user cannot write the root-owned environment.
ENV VIRTUAL_ENV=/opt/dsv41 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=0 \
    UV_NO_CACHE=1 \
    PYTHONDONTWRITEBYTECODE=1
ENV PATH=/opt/dsv41/bin:${PATH}
# The whole environment, by hash, without resolution. Epoch mtimes: FlashInfer's
# JIT cache compares source and object mtimes, so a fresh install would
# otherwise rebuild every op.
RUN --mount=type=bind,source=images/sglang-dsv41,target=/inputs/recipe,readonly \
    python3.12 -I -c 'import json,hashlib; d=json.load(open("/inputs/recipe/source.lock")); assert hashlib.sha256(open("/inputs/recipe/requirements.lock","rb").read()).hexdigest()==d["python"]["requirementsLockSha256"]' \
    && uv venv --python /usr/bin/python3.12 /opt/dsv41 \
    && uv pip install --no-deps --require-hashes -r /inputs/recipe/requirements.lock \
    && find /opt/dsv41 -xdev -exec touch -h -d @0 {} +
# Mooncake's transfer engine links the CUDA 12 runtime from its wheel.
ENV LD_LIBRARY_PATH=/opt/dsv41/lib/python3.12/site-packages/nvidia/cuda_runtime/lib:${LD_LIBRARY_PATH}

# The SGLang source: the locked commit of the public Sglang-public fork.
FROM base AS source
RUN --mount=type=bind,source=images/sglang-dsv41,target=/inputs/recipe,readonly \
    python3.12 -I /inputs/recipe/fetch_source.py --recipe /inputs/recipe --out /src

FROM base
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Confidential Inference SGLang DeepSeek-V4.1"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.base.name="docker.io/nvidia/cuda"
LABEL org.opencontainers.image.base.digest="sha256:7d56ebe2b7cd864a60dca3c8b2d0a39f8fc110417e8253e32505c3387f59119c"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
LABEL ai.confidential.sglang.source="https://github.com/confidential-dot-ai/Sglang-public"
LABEL ai.confidential.sglang.revision="c2425f9b0a274a9f5c3bf91c7af363e94bdbf548"
LABEL ai.confidential.upstream.source="https://github.com/sgl-project/sglang"
LABEL ai.confidential.upstream.revision="a7fd2e1158c389c33077bae67fb797efa8dd09bd"
LABEL ai.confidential.ubuntu.snapshot="20261020T000000Z"
LABEL ai.confidential.python.requirements.sha256="178653143d416fa38c04408a9780ea108268b6154cf9d2afd50cd2af332fbedc"
LABEL ai.confidential.uv.digest="sha256:265d074d08ed8080bc578087ca68a8e94611f9c7be671d40e18b3d3b1ad0dad4"
WORKDIR /opt/sglang
COPY --from=source /src/python /opt/sglang/python
COPY --from=source /src/recipes/deepseek-v41/launcher/hold_engram_cache.py /opt/sglang/recipes/deepseek-v41/launcher/hold_engram_cache.py
COPY --from=source /src/SOURCE_RECORD.json /opt/sglang/SOURCE_RECORD.json
# Editable, as the tested image installed it: workers run with
# PYTHONPATH=/opt/sglang/python. No .git reaches the build, so the version is
# fixed rather than derived from tags.
RUN --mount=type=bind,source=images/sglang/wait_for_model.py,target=/run-src/wait-for-model,readonly \
    SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0.dev0 SGLANG_BUILD_RUST_EXTS=none \
        uv pip install --no-deps --no-build-isolation -e /opt/sglang/python \
    && install -D -m 0555 /run-src/wait-for-model /usr/local/bin/wait-for-model \
    && python -I -c 'import importlib.util as u; assert u.find_spec("sglang") and u.find_spec("mooncake")'
ENV HOME=/tmp
USER 1001:1001
