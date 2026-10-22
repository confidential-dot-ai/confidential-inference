# Log collector image

This image contains the fixed Alloy configuration used by the inference log
collector. The base image is pinned by digest. The configuration reads only
selected application containers. It limits Loki labels, drops sensitive field
markers, redacts Bearer tokens, and sends logs to a Loki push endpoint. The
deployment sets the endpoint, the `deployment` label and the credentials in
the chart's `telemetry` values. `TELEMETRY_AUTH` picks the authentication:
`mtls` (client certificate), `basic` or `oauth2` (client credentials), from
`auth/<type>.alloy`.

Application logging must omit customer payloads. The filter does not detect
all possible secrets in arbitrary text.

The approved `Release images` workflow builds and compares this image twice.
The signed release records it as `images.logCollector`. With
`logCollector.enabled`, the application chart renders the collector, its
service account, log read access and network egress. The deployment provides
the credentials Secret (`telemetry.auth.secretName`).
Changing this pipeline does not require rebuilding gateway or worker images.

After publication, run the pipeline test against that image by digest:

```sh
python3 tests/images/log-collector/test_pipeline.py --image GHCR_IMAGE_AT_DIGEST
```

The test uses local Kubernetes and Loki test servers. `--auth` selects
`mtls` (default), `basic` or `oauth2`. It checks the authentication,
container selection, duplicate prevention, labels, and sensitive data filtering.
It does not build an image or contact a live cluster.
