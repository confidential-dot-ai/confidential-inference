FROM docker.io/grafana/alloy@sha256:5133c159d34c7acf37a1b6d91682abcb6b28b2a29bae152ff5cf4753296f956c
COPY --chmod=0444 config.alloy /etc/alloy/config.alloy
USER 65532:65532
ENTRYPOINT ["/bin/alloy"]
CMD ["run", "/etc/alloy/config.alloy", "--storage.path=/tmp/alloy", "--server.http.listen-addr=127.0.0.1:12345", "--server.http.enable-pprof=false", "--disable-reporting"]
