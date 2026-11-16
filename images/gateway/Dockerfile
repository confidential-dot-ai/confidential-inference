FROM docker.io/library/python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app
WORKDIR /app
COPY services/gateway/requirements.lock /tmp/requirements.lock
RUN python -m pip install --disable-pip-version-check --no-cache-dir --no-compile \
    --require-hashes --only-binary=:all: -r /tmp/requirements.lock && rm /tmp/requirements.lock

ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
RUN case "${SOURCE_REVISION}" in *[!0-9a-f]*|'') exit 64 ;; esac && \
    test "${#SOURCE_REVISION}" -eq 40 && \
    case "${SOURCE_DATE_EPOCH}" in *[!0-9]*|'') exit 64 ;; esac

COPY services/gateway/gateway/__init__.py \
    services/gateway/gateway/config.py \
    services/gateway/gateway/http.py \
    services/gateway/gateway/limits.py \
    services/gateway/gateway/__main__.py \
    services/gateway/gateway/app.py \
    services/gateway/gateway/keys.py \
    services/gateway/gateway/proxy.py \
    services/gateway/gateway/telemetry.py \
    services/gateway/gateway/usage.py /app/gateway/

LABEL org.opencontainers.image.title="Confidential Inference gateway"
LABEL org.opencontainers.image.description="Confidential Inference public API gateway"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="docker.io/library/python:3.13-slim-bookworm"
LABEL org.opencontainers.image.base.digest="sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"

USER 65532:65532
EXPOSE 9443 9090
ENTRYPOINT ["python", "-m", "gateway"]
