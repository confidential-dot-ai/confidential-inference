# Log collector image

This image contains the fixed Alloy configuration used by the inference log
collector. The base image is pinned by digest. The configuration reads only
selected application containers. It limits Loki labels, drops sensitive field
markers, redacts Bearer tokens, and sends logs over mutual TLS.

Application logging must omit customer payloads. The filter does not detect
all possible secrets in arbitrary text.

The approved `Release images` workflow builds and compares this image twice.
The signed release records it as `images.logCollector`. Private deployment
operations install the collector with their existing workload, access rules,
and encrypted client credentials. The application chart does not install it.
Changing this pipeline does not require rebuilding gateway or worker images.

After publication, run the pipeline test against that image by digest:

```sh
python3 tests/images/log-collector/test_pipeline.py --image GHCR_IMAGE_AT_DIGEST
```

The test uses local Kubernetes and Loki test servers. It checks mutual TLS,
container selection, duplicate prevention, labels, and sensitive data filtering.
It does not build an image or contact a live cluster.
