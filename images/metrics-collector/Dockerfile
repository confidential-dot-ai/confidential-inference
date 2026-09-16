FROM docker.io/prom/prometheus@sha256:8672a850efe2f9874702406c8318704edb363587f8c2ca88586b4c8fdb5cea24

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="Confidential Inference metrics collector"
LABEL org.opencontainers.image.description="Pinned Prometheus collector for attested inference metrics"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="docker.io/prom/prometheus"
LABEL org.opencontainers.image.base.digest="sha256:8672a850efe2f9874702406c8318704edb363587f8c2ca88586b4c8fdb5cea24"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
