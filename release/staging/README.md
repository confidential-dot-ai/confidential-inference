# Staging release profile

This profile builds `v0.14.0-staging`. It uses the same pinned public source,
c8s node image, model identity, and SGLang image as `v0.14.0`.

The worker uses the CPU SGLang simulator. It first runs `wait-for-model` against
the encrypted model mount. This check exercises model download, encryption,
placement, opening, and byte-manifest validation without loading the model
weights into the simulator.

Fetch the pinned node measurements into this profile:

```sh
python3 scripts/fetch-node-manifest.py \
  --spec release/staging/spec.yaml \
  --output release/staging/node-manifest.json
```

Generate the exact allowlist with a c8s binary built from the commit in the
profile specification:

```sh
python3 scripts/generate-release-allowlist.py \
  --release release/staging \
  --c8s /path/to/pinned/c8s
```

Build the unsigned manifest for review:

```sh
python3 scripts/build-release-manifest.py \
  --release release/staging \
  --source-commit "$(git rev-parse HEAD)" \
  --output /tmp/v0.14.0-staging-release-manifest.json
```
