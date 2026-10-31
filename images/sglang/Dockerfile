# Build context: the repository root (Dockerfile.dockerignore keeps only this
# recipe, images/sglang/wait_for_model.py and images/sglang/harden_http.py). Every input is pinned: base
# images by linux/amd64 digest, Ubuntu packages by one snapshot timestamp,
# Python wheels by SHA-256, and the SGLang source by one commit of the
# Sglang-public fork with no production source patches.
# images/sglang/harden_http.py then removes the non-serving HTTP routes.
# The image bakes no JIT cache: FlashInfer, Triton and the SGLang JIT kernels
# compile at run time into the pod's emptyDir. FlashInfer's precompiled
# TRT-LLM-gen cubins come from the flashinfer-cubin wheel (requirements.lock):
# the pod has no egress to download them.

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
RUN printf 'deb https://snapshot.ubuntu.com/ubuntu/20261021T000000Z %s main universe\n' \
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
        /var/log/apt /var/log/dpkg.log /var/log/alternatives.log /var/cache/ldconfig/aux-cache \
        /var/cache/fontconfig

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
# otherwise rebuild every op. flashinfer-python and torch-c-dlpack-ext both ship
# a top-level build_backend.py (their PEP 517 build shim, never imported at run
# time); uv installs wheels in parallel, so which copy survives varies between
# builds. The file and both RECORD lines are removed to keep the layer
# reproducible.
RUN --mount=type=bind,source=images/sglang,target=/inputs/recipe,readonly \
    python3.12 -I -c 'import json,hashlib; d=json.load(open("/inputs/recipe/source.lock")); assert hashlib.sha256(open("/inputs/recipe/requirements.lock","rb").read()).hexdigest()==d["python"]["requirementsLockSha256"]' \
    && uv venv --python /usr/bin/python3.12 /opt/dsv41 \
    && uv pip install --no-deps --require-hashes -r /inputs/recipe/requirements.lock \
    && site=/opt/dsv41/lib/python3.12/site-packages \
    && rm "$site/build_backend.py" \
    && sed -i '/^build_backend\.py,/d' "$site"/flashinfer_python-*.dist-info/RECORD "$site"/torch_c_dlpack_ext-*.dist-info/RECORD \
    && ! grep -l '^build_backend\.py,' "$site"/*.dist-info/RECORD \
    && find /opt/dsv41 -xdev -exec touch -h -d @0 {} +
# Mooncake's transfer engine links the CUDA 12 runtime from its wheel.
ENV LD_LIBRARY_PATH=/opt/dsv41/lib/python3.12/site-packages/nvidia/cuda_runtime/lib:${LD_LIBRARY_PATH}

# The SGLang source: the locked commit of the public Sglang-public fork.
FROM base AS source
RUN --mount=type=bind,source=images/sglang,target=/inputs/recipe,readonly \
    python3.12 -I /inputs/recipe/fetch_source.py --recipe /inputs/recipe --out /src

FROM base
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Confidential Inference SGLang"
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
LABEL ai.confidential.ubuntu.snapshot="20261021T000000Z"
LABEL ai.confidential.python.requirements.sha256="83e1fd25ca604fd84a9256fef8bbeff7f4ff7651bd42f01a0783bb1c520b1ad9"
LABEL ai.confidential.sglang.simulator.revision="5e6af31ae3fe8d95f83bab8c78e4db834142b313"
LABEL ai.confidential.sglang.simulator.patch.sha256="7b9116115b440bcfd6b06ff00e410bc779cabe2e2a86ee75d3d8851a4dbe302e"
LABEL ai.confidential.sglang.simulator.parser-flags-noop-patch.sha256="9c654801f916b9d57eb3981dacdde5a3624d5b29e4d352c20822a64ae51f9306"
LABEL ai.confidential.sglang.simulator.prefix-length-patch.sha256="e819be5b7de85d286a10301b1e719dd40c7feaf49a03a1b43dea3b779810e68e"
LABEL ai.confidential.uv.digest="sha256:265d074d08ed8080bc578087ca68a8e94611f9c7be671d40e18b3d3b1ad0dad4"
WORKDIR /opt/sglang
COPY --from=source /src/python /opt/sglang/python
COPY --from=source /src/recipes/deepseek-v41/launcher/hold_engram_cache.py /opt/sglang/recipes/deepseek-v41/launcher/hold_engram_cache.py
COPY --from=source /src/SOURCE_RECORD.json /opt/sglang/SOURCE_RECORD.json
# Editable, as the tested image installed it: workers run with
# PYTHONPATH=/opt/sglang/python. No .git reaches the build, so the version is
# fixed rather than derived from tags. uv_cache.json holds the build-time
# ctime of pyproject.toml (uv's reinstall check, never used in the image), so
# it leaves the dist-info and its RECORD line. The import check runs with -B:
# -I ignores PYTHONDONTWRITEBYTECODE.
RUN --mount=type=bind,source=images/sglang/harden_http.py,target=/run-src/harden-http.py,readonly \
    --mount=type=bind,source=images/sglang/wait_for_model.py,target=/run-src/wait-for-model,readonly \
    SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0.dev0 SGLANG_BUILD_RUST_EXTS=none \
        uv pip install --no-deps --no-build-isolation -e /opt/sglang/python \
    && python /run-src/harden-http.py --root /opt/sglang/python/sglang --variant pd \
    && dist=/opt/dsv41/lib/python3.12/site-packages/sglang-0.0.0.dev0.dist-info \
    && rm "$dist/uv_cache.json" \
    && sed -i '/^sglang-0\.0\.0\.dev0\.dist-info\/uv_cache\.json,/d' "$dist/RECORD" \
    && install -D -m 0555 /run-src/wait-for-model /usr/local/bin/wait-for-model \
    && python -I -B -c 'import importlib.util as u; assert u.find_spec("sglang") and u.find_spec("mooncake")'
# CPU staging uses the same image. Its simulator is outside the production
# import path and is enabled only by the staging PYTHONPATH.
RUN --mount=type=bind,source=images/sglang/simulator-upstream,target=/run-src/sglang-simulator,readonly \
    --mount=type=bind,source=images/sglang/patches,target=/run-src/patches,readonly \
    --mount=type=bind,source=images/sglang/fetch_model.py,target=/run-src/fetch-model,readonly \
    install -d -m 0755 /opt/confidential-inference/sglang-simulator \
    && cp -a /run-src/sglang-simulator/. /opt/confidential-inference/sglang-simulator/ \
    && cd /opt/confidential-inference/sglang-simulator \
    && git apply --check /run-src/patches/sglang-simulator-replay-only.patch \
    && git apply /run-src/patches/sglang-simulator-replay-only.patch \
    && git apply --check /run-src/patches/sglang-simulator-parser-flags-noop.patch \
    && git apply /run-src/patches/sglang-simulator-parser-flags-noop.patch \
    && git apply --check /run-src/patches/sglang-simulator-prefix-length.patch \
    && git apply /run-src/patches/sglang-simulator-prefix-length.patch \
    && install -D -m 0555 /run-src/fetch-model /usr/local/bin/fetch-model
ENV HOME=/tmp
USER 1001:1001
