# Kube-State Metrics Image

This image wraps the exact kube-state-metrics image used by the cluster. The
pinned base digest, build tools, source commit, and normalized timestamp make
the final OCI platform manifest reproducible.

Use `.github/workflows/release-images.yml` to build and publish it. The workflow
builds it twice and requires equal platform digests before publication.
