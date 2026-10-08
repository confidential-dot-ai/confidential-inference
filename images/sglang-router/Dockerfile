FROM docker.io/library/rust@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS build

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dev python3-venv clang protobuf-compiler \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/build \
    && /opt/build/bin/pip install maturin==1.9.6
WORKDIR /src
COPY source.lock /inputs/source.lock
COPY patches /inputs/patches
RUN python3 -c 'import json,hashlib,pathlib; d=json.load(open("/inputs/source.lock")); p=pathlib.Path("/inputs")/d["patch"]["path"]; assert hashlib.sha256(p.read_bytes()).hexdigest()==d["patch"]["sha256"]' \
    && git init . \
    && git remote add origin https://github.com/sgl-project/sglang \
    && router_commit="$(python3 -c 'import json,re; c=json.load(open("/inputs/source.lock"))["source"]["commit"]; assert re.fullmatch("[0-9a-f]{40}",c); print(c)')" \
    && git fetch --depth=1 origin "${router_commit}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${router_commit}" \
    && git apply --check /inputs/patches/worker-withdrawal.patch \
    && git apply /inputs/patches/worker-withdrawal.patch
COPY Cargo.lock /src/sgl-model-gateway/Cargo.lock
RUN python3 -c 'import json,hashlib,pathlib; d=json.load(open("/inputs/source.lock")); assert hashlib.sha256(pathlib.Path("/src/sgl-model-gateway/Cargo.lock").read_bytes()).hexdigest()==d["cargoLockSha256"]'
ENV RUSTFLAGS="--remap-path-prefix=/src=/usr/src/sglang"
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/sgl-model-gateway/target,sharing=locked \
    /opt/build/bin/maturin build --locked --release --features vendored-openssl \
    --manifest-path sgl-model-gateway/bindings/python/Cargo.toml --out /out

FROM docker.io/library/python@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Confidential Inference SGLang Router"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="docker.io/library/python"
LABEL org.opencontainers.image.base.digest="sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258"
COPY requirements.lock /router-requirements.lock
RUN python3 -m pip install --no-cache-dir --require-hashes -r /router-requirements.lock
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
COPY --from=build /out /router-wheels
RUN python3 -m pip install --no-deps --force-reinstall /router-wheels/*.whl \
    && rm -rf /router-wheels
USER 1001:1001
EXPOSE 30000 29000
ENTRYPOINT ["python3", "-m", "sglang_router.launch_router"]
