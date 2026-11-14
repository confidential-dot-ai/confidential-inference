# The Qwen3.5-0.8B staging worker: one GPU, behind the SGLang router.
#
# Build context: the repository root (Dockerfile.dockerignore keeps only the
# files named below). The engine is the production worker's engine: the
# stages up to "FROM base" and the SGLang install step are copied unchanged
# from images/sglang/Dockerfile and read the same pinned inputs
# (images/sglang/source.lock, requirements.lock, fetch_source.py,
# harden_http.py, harden_media.py, harden_dist.py, wait_for_model.py, fetch_model.py, dcgm-counters.csv).
# tests/images/sglang/test_qwen35_recipe.py checks that they stay identical,
# so the shared layers have the same bytes as the production image's layers.
#
# What this image adds: the byte manifest of the pinned model revision and
# qwen35-serve, a helper for `docker run` outside Kubernetes. The chart does
# not use the helper; it renders the same worker argv itself
# (tests/fixtures/deployments/qwen35-staging-values.yaml). What it drops: the
# CPU simulator, which only the simulator staging profile uses.
#
# The model weights are not in the image. The worker downloads them at start
# (inference.model.download) or reads a C8s model volume, and wait-for-model
# checks every byte against model-manifest.json before SGLang starts.

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

# The SGLang source: the locked official upstream commit.
FROM base AS source
RUN --mount=type=bind,source=images/sglang,target=/inputs/recipe,readonly \
    python3.12 -I /inputs/recipe/fetch_source.py --recipe /inputs/recipe --out /src

FROM base
RUN --mount=type=bind,from=dcgm-exporter,source=/,target=/run-dcgm,readonly \
    --mount=type=bind,source=images/sglang/dcgm-counters.csv,target=/run-src/dcgm-counters.csv,readonly \
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
LABEL org.opencontainers.image.title="Confidential Inference SGLang Qwen3.5-0.8B staging"
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
LABEL ai.confidential.uv.digest="sha256:265d074d08ed8080bc578087ca68a8e94611f9c7be671d40e18b3d3b1ad0dad4"
LABEL ai.confidential.model.repository="Qwen/Qwen3.5-0.8B"
LABEL ai.confidential.model.revision="2fc06364715b967f1860aea9cf38778875588b17"
LABEL ai.confidential.model.manifest.sha256="625963f6a7f159fd2a3e8ad97642a11ac275d1735adaadca8df39452b9fbd8fa"
WORKDIR /opt/sglang
COPY --from=source /src/python /opt/sglang/python
COPY --from=source /src/SOURCE_RECORD.json /opt/sglang/SOURCE_RECORD.json
# Editable, as the tested image installed it: workers run with
# PYTHONPATH=/opt/sglang/python. No .git reaches the build, so the version is
# fixed rather than derived from tags. uv_cache.json holds the build-time
# ctime of pyproject.toml (uv's reinstall check, never used in the image), so
# it leaves the dist-info and its RECORD line. The import check runs with -B:
# -I ignores PYTHONDONTWRITEBYTECODE.
RUN --mount=type=bind,source=images/sglang/harden_http.py,target=/run-src/harden-http.py,readonly \
    --mount=type=bind,source=images/sglang/harden_media.py,target=/run-src/harden-media.py,readonly \
    --mount=type=bind,source=images/sglang/harden_dist.py,target=/run-src/harden-dist.py,readonly \
    --mount=type=bind,source=images/sglang/wait_for_model.py,target=/run-src/wait-for-model,readonly \
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
# The model pin and the docker-run helper. fetch-model is the chart's model
# download tool, as in the production image.
RUN --mount=type=bind,source=images/sglang/fetch_model.py,target=/run-src/fetch-model,readonly \
    --mount=type=bind,source=images/sglang-qwen35/model-manifest.json,target=/run-src/model-manifest.json,readonly \
    --mount=type=bind,source=images/sglang-qwen35/serve.sh,target=/run-src/serve.sh,readonly \
    install -D -m 0555 /run-src/fetch-model /usr/local/bin/fetch-model \
    && install -D -m 0444 /run-src/model-manifest.json /opt/confidential-inference/qwen35-0.8b/model-manifest.json \
    && install -D -m 0555 /run-src/serve.sh /usr/local/bin/qwen35-serve \
    && python -B -c 'import sglang.srt.models.qwen3_5, sglang.srt.function_call.qwen3_coder_detector'
ENV HOME=/tmp
USER 1001:1001
