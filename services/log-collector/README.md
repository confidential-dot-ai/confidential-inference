# Application log collector

This image contains a fixed Grafana Alloy configuration. Enable it with
`logCollector.enabled`, a digest-pinned `logCollector.image`, a stable
`deploymentId`, and the matching deployment log URL.

The service account can read pods and pod logs in the release namespace.
It cannot read Secrets or execute commands. The collector selects the shared
application label and reads only the main application containers. It excludes itself and
certificate, secret, and volume helpers.

The collector sends logs through the admin mTLS ingress. It uses the existing
metrics client certificate Secret. Each record has four labels: deployment,
namespace, pod, and container. The deployment ID stays the same at promotion.
The destination store must remain separate from the old production store.

The configuration drops lines with known sensitive field markers and removes
Bearer tokens. These rules cannot detect all secrets in arbitrary text.
Applications must not log customer payloads or credentials.

Run `python3 services/log-collector/test_pipeline.py` after building
`candidate-log-collector:test`. The test runs the actual image against local
TLS Kubernetes and mTLS Loki servers. It verifies container selection,
filtering, delivery, labels, and one read for a container with several ports.
It requires Docker, Python cryptography, and the system Snappy library.

The storage directory is temporary. Pod replacement can read recent logs
again. The test does not prove exactly-once delivery across restarts.
