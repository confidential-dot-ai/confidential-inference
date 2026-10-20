FROM docker.io/library/python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Confidential Inference rollout client"
LABEL org.opencontainers.image.description="Python runtime for the exact client command pinned in a transition policy"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="docker.io/library/python"
LABEL org.opencontainers.image.base.digest="sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"
