# Staging release profile

This profile builds `vX.Y.Z-staging`. It is a layer on top of `release/`
(`release/profiles.json`). `spec.yaml` sets only the version and the public
hostnames, and `values.yaml` sets only the staging values. Every other value,
including the image digests, the c8s release, the node manifest, and the model
identity, comes from `release/`.

The worker uses the CPU SGLang simulator. It first runs `wait-for-model` against
the encrypted model mount. This check exercises model download, encryption,
placement, opening, and byte-manifest validation without loading the model
weights into the simulator.

Render the staging chart with both values files, in this order:

```sh
helm template confidential-inference helm/confidential-inference \
  --values release/values.yaml --values release/staging/values.yaml
```

`scripts/release_profiles.py resolve --release release/staging` prints the
values files in order.

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
  --image-publication /path/to/image-publication-manifest.json \
  --output /tmp/staging-release-manifest.json
```

To move staging ahead of production, set `c8s` or `imageSourceCommit` in this
`spec.yaml`, and the matching image digests in this `values.yaml`. Then fetch
the node manifest into this directory:

```sh
python3 scripts/fetch-node-manifest.py --release release/staging
```
