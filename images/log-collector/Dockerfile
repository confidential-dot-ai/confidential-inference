FROM docker.io/grafana/alloy@sha256:5133c159d34c7acf37a1b6d91682abcb6b28b2a29bae152ff5cf4753296f956c
ARG SOURCE_REVISION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Confidential Inference log collector"
LABEL org.opencontainers.image.description="Pinned operational log pipeline with sensitive field filtering"
LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"
LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"
LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.base.name="docker.io/grafana/alloy"
LABEL org.opencontainers.image.base.digest="sha256:5133c159d34c7acf37a1b6d91682abcb6b28b2a29bae152ff5cf4753296f956c"
LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"

COPY --chmod=0444 config.alloy /etc/alloy/config.alloy
USER 65532:65532
ENTRYPOINT ["/bin/alloy"]
CMD ["run", "/etc/alloy/config.alloy", "--storage.path=/tmp/alloy", "--server.http.listen-addr=127.0.0.1:12345", "--server.http.enable-pprof=false", "--disable-reporting"]
