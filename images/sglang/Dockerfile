FROM docker.io/lmsysorg/sglang@sha256:bde16a8447b19e89056b9eea06c72be6c02801dc89d528c9ea90c53368fd74bf

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="Confidential Inference SGLang"
LABEL org.opencontainers.image.description="Role-neutral SGLang v0.5.18 image with reviewed confidential-compute fixes"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
LABEL ai.confidential.upstream.source="https://github.com/sgl-project/sglang"
LABEL ai.confidential.upstream.revision="71de97b264b04dcd514cf904003028aefe9775c8"
LABEL ai.confidential.sglang.async-d2h.revision="aea6d45cde342a1455186e7b9e3c3191b8c97f8d"
LABEL ai.confidential.sglang.flashinfer-cc.revision="64121c62a8dca7f5d1fdd39c8155ac3b8fc9da70"
LABEL ai.confidential.sglang.patch.sha256="da0afb59209a6bce8a910b21c6e63fcde768f5b82675bfa2bd22ae230c978570"
LABEL ai.confidential.sglang.simulator.revision="5e6af31ae3fe8d95f83bab8c78e4db834142b313"
LABEL ai.confidential.sglang.simulator.patch.sha256="7b9116115b440bcfd6b06ff00e410bc779cabe2e2a86ee75d3d8851a4dbe302e"
LABEL ai.confidential.sglang.simulator.parser-flags-noop-patch.sha256="9c654801f916b9d57eb3981dacdde5a3624d5b29e4d352c20822a64ae51f9306"
LABEL ai.confidential.flashinfer.version="0.6.17"
LABEL ai.confidential.flashinfer.revision="a0a6b019b9b27d49d209f85d028a1ae5a9b347d7"
LABEL ai.confidential.flashinfer.cuda-ipc-patch.sha256="62d607a31de4662de8e54a70140b72cc7bfd87cdad5d5850e0e0893f0a13bfff"
LABEL org.opencontainers.image.base.name="docker.io/lmsysorg/sglang"
LABEL org.opencontainers.image.base.digest="sha256:bde16a8447b19e89056b9eea06c72be6c02801dc89d528c9ea90c53368fd74bf"

RUN --mount=type=bind,source=patches/cc-optimizations-v0518.patch,target=/run-src/cc-optimizations.patch,readonly \
    --mount=type=bind,source=patch_flashinfer_cuda_ipc.py,target=/run-src/patch-flashinfer-cuda-ipc.py,readonly \
    --mount=type=bind,source=wait_for_model.py,target=/run-src/wait-for-model,readonly \
    --mount=type=bind,source=gpu_metrics.py,target=/run-src/gpu-metrics,readonly \
    --mount=type=bind,source=simulator-upstream,target=/run-src/sglang-simulator,readonly \
    --mount=type=bind,source=patches/sglang-simulator-replay-only.patch,target=/run-src/sglang-simulator-replay-only.patch,readonly \
    --mount=type=bind,source=patches/sglang-simulator-parser-flags-noop.patch,target=/run-src/sglang-simulator-parser-flags-noop.patch,readonly \
    install -D -m 0644 /run-src/cc-optimizations.patch /tmp/cc-optimizations.patch \
    && install -D -m 0644 /run-src/patch-flashinfer-cuda-ipc.py /tmp/patch-flashinfer-cuda-ipc.py \
    && cd /sgl-workspace/sglang \
    && git apply --check --directory=python /tmp/cc-optimizations.patch \
    && git apply --directory=python /tmp/cc-optimizations.patch \
    && cd python \
    && python3 -c 'from pathlib import Path; files=["sglang/srt/distributed/device_communicators/cuda_wrapper.py","sglang/srt/layers/flashinfer_comm_fusion.py","sglang/srt/managers/async_d2h_copy_worker.py","sglang/srt/managers/scheduler.py","sglang/srt/managers/utils.py","sglang/srt/utils/common.py"]; [compile(Path(name).read_text(encoding="utf-8"), name, "exec") for name in files]' \
    && python3 /tmp/patch-flashinfer-cuda-ipc.py \
    && python3 -c 'import ctypes; path="/usr/local/cuda/targets/x86_64-linux/lib/libcudart.so"; library=ctypes.CDLL(path); assert getattr(library, "cudaDeviceReset", None) is not None' \
    && install -d -m 0755 /opt/confidential-inference/sglang-simulator \
    && cp -a /run-src/sglang-simulator/. /opt/confidential-inference/sglang-simulator/ \
    && cd /opt/confidential-inference/sglang-simulator \
    && git apply --check /run-src/sglang-simulator-replay-only.patch \
    && git apply /run-src/sglang-simulator-replay-only.patch \
    && git apply --check /run-src/sglang-simulator-parser-flags-noop.patch \
    && git apply /run-src/sglang-simulator-parser-flags-noop.patch \
    && install -D -m 0555 /run-src/wait-for-model /usr/local/bin/wait-for-model \
    && install -D -m 0555 /run-src/gpu-metrics /usr/local/bin/gpu-metrics \
    && rm /tmp/cc-optimizations.patch /tmp/patch-flashinfer-cuda-ipc.py
