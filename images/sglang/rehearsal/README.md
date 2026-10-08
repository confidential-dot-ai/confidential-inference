# Worker update rehearsal image

This recipe changes only OCI labels on the exact worker artifact used by the
candidate. It preserves that artifact's files, startup, and GPU fixes. The
output has a distinct digest for testing image admission and worker replacement.
It is a development artifact, not a signed Confidential Inference release.

Commit the recipe before use. Use a registry login whose Docker configuration
is in tmpfs. Run:

```sh
python3 images/sglang/rehearsal/build.py --receipt /protected/path/worker-image.json
```

The script checks the base pin and rejects tracked recipe changes. It publishes
an image tagged by source commit. The receipt records the immutable image
reference, base, source, total build time, and failed attempts. Keep receipts.
This build does not deploy a worker or change any cluster.
