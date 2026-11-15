# The Qwen3.5-0.8B staging worker: one GPU, behind the SGLang router.
#
# STAGING ONLY, and temporary: the model weights are inside the image until
# a model mirror or persistent model disks exist.
#
# This file is images/sglang-dsv41-flash/Dockerfile verbatim (between the two
# marker lines), then one stage FROM its production stage `engine`. The engine
# layers are therefore the production layers: the same instructions on the
# same pinned inputs, built with the same reproducible settings.
# tests/images/sglang-qwen35-0.8b/test_recipe.py fails if the copy differs.
#
# The staging stage adds ONE layer: the Qwen/Qwen3.5-0.8B files at revision
# 2fc06364715b967f1860aea9cf38778875588b17. The production image's fetch-model
# downloads them from Hugging Face at build time and checks each file's size
# and SHA-256 against model-manifest.json, whose own SHA-256 is pinned below.
# The weight files are never in Git: only the byte manifest is. The files get
# fixed owner, modes and times, so two clean builds give the same bytes. The
# pod needs no download, no egress and no init container: wait-for-model
# --image-files checks every byte against the manifest again at each start.
# The same step imports the Qwen3.5 model and its tool parser from upstream
# SGLang; /tmp is a build-time tmpfs, so the import leaves no file behind.
#
# Build context: the repository root (Dockerfile.dockerignore: the production
# inputs and the two files of this recipe).

# ---- begin images/sglang-dsv41-flash/Dockerfile (verbatim) ----
# Build context: the repository root (Dockerfile.dockerignore keeps only this
# recipe, images/sglang-dsv41-flash/wait_for_model.py and the images/sglang-dsv41-flash/harden_*.py
# build steps). Every input is pinned: base
# images by linux/amd64 digest, Ubuntu packages by one snapshot timestamp,
# Python wheels by SHA-256, and the SGLang source by one commit of the
# official upstream repository with no inference source patches.
# images/sglang-dsv41-flash/harden_http.py then removes the non-serving HTTP routes.
# images/sglang-dsv41-flash/harden_media.py limits request media to inline data.
# images/sglang-dsv41-flash/harden_dist.py keeps internal distributed listeners on loopback.
# The image bakes no JIT cache: FlashInfer, Triton and the SGLang JIT kernels
# compile at run time into the pod's emptyDir. FlashInfer's precompiled
# TRT-LLM-gen cubins come from the flashinfer-cubin wheel (requirements.lock):
# the pod has no egress to download them.

FROM ghcr.io/astral-sh/uv@sha256:265d074d08ed8080bc578087ca68a8e94611f9c7be671d40e18b3d3b1ad0dad4 AS uv
FROM nvcr.io/nvidia/k8s/dcgm-exporter@sha256:148b0c025e5f2850256816fa33754fbf4733b7a086697a95613fc0ba3db5b003 AS dcgm-exporter

# The CUDA 13.0.3 toolkit the image was tested with. Kernels compile against it
# at run time, so this is the devel image.
FROM docker.io/nvidia/cuda@sha256:7d56ebe2b7cd864a60dca3c8b2d0a39f8fc110417e8253e32505c3387f59119c AS base
ENV DEBIAN_FRONTEND=noninteractive
# Ubuntu packages come from one snapshot.ubuntu.com timestamp (source.lock
# ubuntuSnapshot), never the moving archive. The base image's NVIDIA apt
# source is not read. The upgrade brings the CUDA base image's own packages
# to the snapshot's security fixes. Mooncake links ibverbs/mlx5, libnl, numa and curl even
# for intra-node NVLink; FFmpeg keeps torchcodec's import quiet; the OpenSSL
# headers serve the HiCache hash extension's JIT build; git serves the
# source stage.
RUN printf 'deb https://snapshot.ubuntu.com/ubuntu/20261104T000000Z %s main universe\n' \
        noble noble-updates noble-security > /tmp/snapshot.list \
    && apt-get -o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/dev/null \
        -o Acquire::Check-Valid-Until=false update \
    && apt-get -o Dir::Etc::SourceList=/tmp/snapshot.list -o Dir::Etc::SourceParts=/dev/null \
        upgrade -y --no-install-recommends \
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
RUN --mount=type=bind,source=images/sglang-dsv41-flash,target=/inputs/recipe,readonly \
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

# The SGLang source: the locked official upstream commit.
FROM base AS source
RUN --mount=type=bind,source=images/sglang-dsv41-flash,target=/inputs/recipe,readonly \
    python3.12 -I /inputs/recipe/fetch_source.py --recipe /inputs/recipe --out /src

# The production image. images/sglang-qwen35-0.8b/Dockerfile holds this file
# verbatim and builds its staging image FROM this stage.
FROM base AS engine
RUN --mount=type=bind,from=dcgm-exporter,source=/,target=/run-dcgm,readonly \
    --mount=type=bind,source=images/sglang-dsv41-flash/dcgm-counters.csv,target=/run-src/dcgm-counters.csv,readonly \
    install -D -m 0555 /run-dcgm/usr/bin/dcgm-exporter /usr/local/bin/dcgm-exporter \
    && install -d -m 0755 /opt/dcgm/lib \
    && cp -a /run-dcgm/usr/lib/x86_64-linux-gnu/libdcgm* /run-dcgm/usr/lib/x86_64-linux-gnu/libnvperf_* /opt/dcgm/lib/ \
    && cp -a /run-dcgm/licenses /opt/dcgm/licenses \
    && install -D -m 0644 /run-src/dcgm-counters.csv /etc/dcgm-exporter/counters.csv \
    && find /opt/dcgm /etc/dcgm-exporter -xdev -exec touch -h -d @0 {} + \
    && touch -d @0 /usr/local/bin/dcgm-exporter
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV CI_DIAGNOSTIC_SOURCE_REVISION=${SOURCE_REVISION}
LABEL org.opencontainers.image.title="Confidential Inference SGLang"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.base.name="docker.io/nvidia/cuda"
LABEL org.opencontainers.image.base.digest="sha256:7d56ebe2b7cd864a60dca3c8b2d0a39f8fc110417e8253e32505c3387f59119c"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
LABEL ai.confidential.sglang.source="https://github.com/sgl-project/sglang"
LABEL ai.confidential.sglang.revision="a7fd2e1158c389c33077bae67fb797efa8dd09bd"
LABEL ai.confidential.upstream.source="https://github.com/sgl-project/sglang"
LABEL ai.confidential.upstream.revision="a7fd2e1158c389c33077bae67fb797efa8dd09bd"
LABEL ai.confidential.ubuntu.snapshot="20261104T000000Z"
LABEL ai.confidential.python.requirements.sha256="83e1fd25ca604fd84a9256fef8bbeff7f4ff7651bd42f01a0783bb1c520b1ad9"
LABEL ai.confidential.sglang.simulator.revision="5e6af31ae3fe8d95f83bab8c78e4db834142b313"
LABEL ai.confidential.sglang.simulator.patch.sha256="7b9116115b440bcfd6b06ff00e410bc779cabe2e2a86ee75d3d8851a4dbe302e"
LABEL ai.confidential.sglang.simulator.parser-flags-noop-patch.sha256="9c654801f916b9d57eb3981dacdde5a3624d5b29e4d352c20822a64ae51f9306"
LABEL ai.confidential.sglang.simulator.prefix-length-patch.sha256="e819be5b7de85d286a10301b1e719dd40c7feaf49a03a1b43dea3b779810e68e"
LABEL ai.confidential.uv.digest="sha256:265d074d08ed8080bc578087ca68a8e94611f9c7be671d40e18b3d3b1ad0dad4"
WORKDIR /opt/sglang
COPY --from=source /src/python /opt/sglang/python
COPY --from=source /src/SOURCE_RECORD.json /opt/sglang/SOURCE_RECORD.json
# Editable, as the tested image installed it: workers run with
# PYTHONPATH=/opt/sglang/python. No .git reaches the build, so the version is
# fixed rather than derived from tags. uv_cache.json holds the build-time
# ctime of pyproject.toml (uv's reinstall check, never used in the image), so
# it leaves the dist-info and its RECORD line. The import check runs with -B:
# -I ignores PYTHONDONTWRITEBYTECODE.
RUN --mount=type=bind,source=images/sglang-dsv41-flash/harden_http.py,target=/run-src/harden-http.py,readonly \
    --mount=type=bind,source=images/sglang-dsv41-flash/harden_media.py,target=/run-src/harden-media.py,readonly \
    --mount=type=bind,source=images/sglang-dsv41-flash/harden_dist.py,target=/run-src/harden-dist.py,readonly \
    --mount=type=bind,source=images/sglang-dsv41-flash/wait_for_model.py,target=/run-src/wait-for-model,readonly \
    --mount=type=bind,source=images/sglang-router/private_log_sink.py,target=/run-src/private_log_sink.py,readonly \
    SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0.dev0 SGLANG_BUILD_RUST_EXTS=none \
        uv pip install --no-deps --no-build-isolation -e /opt/sglang/python \
    && python /run-src/harden-http.py --root /opt/sglang/python/sglang --variant pd \
    && python /run-src/harden-media.py --root /opt/sglang/python/sglang \
    && python /run-src/harden-dist.py --root /opt/sglang/python/sglang \
    && chmod -R go-w /opt/sglang/python \
    && dist=/opt/dsv41/lib/python3.12/site-packages/sglang-0.0.0.dev0.dist-info \
    && rm "$dist/uv_cache.json" \
    && sed -i '/^sglang-0\.0\.0\.dev0\.dist-info\/uv_cache\.json,/d' "$dist/RECORD" \
    && install -D -m 0555 /run-src/wait-for-model /usr/local/bin/wait-for-model \
    && install -D -m 0444 /run-src/private_log_sink.py /usr/local/bin/private_log_sink.py \
    && python -I -B -c 'import importlib.util as u; assert u.find_spec("sglang") and u.find_spec("mooncake")'
# CPU staging uses the same image. Its simulator is outside the production
# import path and is enabled only by the staging PYTHONPATH.
RUN --mount=type=bind,source=images/sglang-dsv41-flash/simulator-upstream,target=/run-src/sglang-simulator,readonly \
    --mount=type=bind,source=images/sglang-dsv41-flash/patches,target=/run-src/patches,readonly \
    --mount=type=bind,source=images/sglang-dsv41-flash/fetch_model.py,target=/run-src/fetch-model,readonly \
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
# ---- end images/sglang-dsv41-flash/Dockerfile ----

FROM engine AS qwen35-0.8b
USER 0:0
RUN --mount=type=bind,source=images/sglang-qwen35-0.8b/model-manifest.json,target=/run-src/model-manifest.json,readonly \
    --mount=type=bind,source=images/sglang-qwen35-0.8b/serve.sh,target=/run-src/serve.sh,readonly \
    --mount=type=tmpfs,target=/tmp \
    models=/opt/confidential-inference/models \
    && install -d -m 0755 "$models/qwen35-0.8b" \
    && /usr/local/bin/fetch-model fetch \
        --path="$models/qwen35-0.8b" \
        --manifest=/run-src/model-manifest.json \
        --manifest-sha256=625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa \
        --revision-metadata=.model-lock-local-manifest.json \
    && install -D -m 0555 /run-src/serve.sh /usr/local/bin/qwen35-serve \
    && chown -R 0:0 "$models" \
    && find "$models" -type d -exec chmod 0555 {} + \
    && find "$models" -type f -exec chmod 0444 {} + \
    && find "$models" -exec touch -h -d @0 {} + \
    && touch -h -d @0 /opt/confidential-inference /usr/local/bin /usr/local/bin/qwen35-serve \
    && HOME=/tmp python -B -c 'import sglang.srt.models.qwen3_5, sglang.srt.function_call.qwen3_coder_detector'
LABEL org.opencontainers.image.title="Confidential Inference SGLang Qwen3.5-0.8B staging"
LABEL ai.confidential.model.repository="Qwen/Qwen3.5-0.8B"
LABEL ai.confidential.model.revision="2fc06364715b967f1860aea9cf38778875588b17"
LABEL ai.confidential.model.manifest.sha256="625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"
LABEL ai.confidential.model.path="/opt/confidential-inference/models/qwen35-0.8b"
USER 1001:1001
