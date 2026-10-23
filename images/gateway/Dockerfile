FROM docker.io/library/rust@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS build

WORKDIR /workspace

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
RUN case "${SOURCE_REVISION}" in *[!0-9a-f]*|'') exit 64 ;; esac && \
    test "${#SOURCE_REVISION}" -eq 40 && \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 64 ;; esac

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY services/gateway/Cargo.toml services/gateway/Cargo.toml
COPY services/gateway/src services/gateway/src
COPY services/maintenance-gateway/Cargo.toml services/maintenance-gateway/Cargo.toml
COPY services/maintenance-gateway/src services/maintenance-gateway/src

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/workspace/target,sharing=locked \
    cargo build --locked --release --package confidential-gateway --bin confidential-gateway && \
    install -D -m 0755 target/release/confidential-gateway /out/confidential-gateway

FROM gcr.io/distroless/cc-debian12@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Confidential Inference gateway"
LABEL org.opencontainers.image.description="Public API gateway for the Confidential Inference c8s workload"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12"
LABEL org.opencontainers.image.base.digest="sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"
LABEL ai.confidential.build.rust.digest="sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"

COPY --from=build --chown=65532:65532 /out/confidential-gateway /usr/local/bin/confidential-gateway

USER 65532:65532
EXPOSE 9443 9090
ENTRYPOINT ["/usr/local/bin/confidential-gateway"]
