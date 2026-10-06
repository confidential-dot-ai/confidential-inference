# Staging release profile

This profile builds `vX.Y.Z-staging`. It is a layer on top of `release/`
(`release/profiles.json`). `spec.yaml` sets the version, the public
hostnames, and the model, and `values.yaml` sets the staging values. Every
other value, including the image names, the c8s release, and the node
manifest, comes from `release/`. The release build adds the image digests.

Staging mounts a small public model
(`hf-internal-testing/tiny-random-LlamaForCausalLM`, 14.9 MB), not the
production model.

The worker uses the CPU SGLang simulator. It first runs `wait-for-model` against
the encrypted model mount. This check exercises model download, encryption,
placement, opening, and byte-manifest validation without loading the model
weights into the simulator.

Render the staging chart with both values files and the
`release-values.yaml` asset of the release, in this order:

```sh
helm template confidential-inference helm/confidential-inference \
  --values release/values.yaml --values release/staging/values.yaml \
  --values release-values.yaml
```

`scripts/release_profiles.py resolve --release release/staging` prints the
values files in order.

The release build generates the exact allowlist and the manifest. See
`release/README.md` for the command that builds the release again:

```sh
python3 scripts/build-release-manifest.py \
  --release release/staging \
  --source-commit "$(git rev-parse HEAD)" \
  --image-publication /path/to/image-publication-manifest.json \
  --c8s /path/to/pinned/c8s \
  --output-dir /tmp/staging-release
```

To move staging ahead of production, set `c8s` in this `spec.yaml`. Then
fetch the node manifest into this directory:

```sh
python3 scripts/fetch-node-manifest.py --release release/staging
```
