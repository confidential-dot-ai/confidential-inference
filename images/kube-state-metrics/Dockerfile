FROM registry.k8s.io/kube-state-metrics/kube-state-metrics@sha256:44cfc22900bf545fb9a073adea2132b80558b7e9b6a6f687a8f23b4d7fc438c9

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH

LABEL org.opencontainers.image.title="Confidential Inference kube-state metrics"
LABEL org.opencontainers.image.description="Pinned kube-state-metrics collector for attested cluster metrics"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="registry.k8s.io/kube-state-metrics/kube-state-metrics"
LABEL org.opencontainers.image.base.digest="sha256:44cfc22900bf545fb9a073adea2132b80558b7e9b6a6f687a8f23b4d7fc438c9"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
