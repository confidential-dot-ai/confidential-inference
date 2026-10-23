# Staging release profile

This profile builds `vX.Y.Z-staging`. It is a layer on top of `release/`
(`release/profiles.json`). The tag is the version. `spec.yaml` sets the
public hostnames and the model, and `values.yaml` sets the staging values. Every
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
values files in order. The release publishes both files as assets
(`profile-values-release-values.yaml`, `profile-values-release-staging-values.yaml`)
and the chart as a package, so the same render needs no checkout:

```sh
helm pull oci://ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference \
  --version X.Y.Z
helm template confidential-inference confidential-inference-X.Y.Z.tgz \
  --values profile-values-release-values.yaml \
  --values profile-values-release-staging-values.yaml \
  --values release-values.yaml
```

Check each asset against the signed manifest first: the package SHA-256 is
`chart.archiveSha256`, each values file is in `profileValues`.

The release build generates the exact allowlist and the manifest. See
`release/README.md` for the command that builds the release again:

```sh
python3 scripts/build-release-manifest.py \
  --tag vX.Y.Z-staging \
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

## Runtime configuration and attestation

The staging profile enables the gateway and router file readers. It clears
production model routes and uses the small staging model for both the public
model name and the worker route. Helm creates `gateway-runtime` and
`router-model-routes`. The existing Application Deployment workflow must
create `gateway-release-selection` from verified signed release assets before
it starts the gateway. Do not copy release metadata from a running pod.

Applications serve plain HTTP inside their pods. The c8s per-pod mesh
(c8s v0.64 and later) carries every pod-to-pod connection over mutual TLS and
mounts `/etc/c8s/certs` only into its own sidecars. Keep exact environment and
mount rules, the gateway pepper secret grant, and encrypted-volume inputs.

Refresh the image configuration record with the dependency bump. Preserve
strict policy lint and verify that arbitrary component command overrides fail.

The allowlist mirrors the node image's seed recorded in
`release/inputs/c8s-seeds/<source-commit>.json`. `scripts/pin-local-c8s.py`
records it from the build directory's `allowlist-seed.json`. Delete a record
when no profile pins its commit.

## In-cluster validation client

The final staging release declares `Deployment/gateway-update-agent`, its
read-only ServiceAccount, and its NetworkPolicies. Production disables it.
The client uses the pipeline-built `rolloutClient` image. Its complete Python
program, environment, and mounts are signed in the generated allowlist.

Workflow 3 submits `{"id": "...", "actions": [...]}` through the
`gateway-update-task` Secret. The account can get only that Secret. The client
writes `{"taskId": "...", "results": [...]}` to container `client` logs.
Read these with `kubectl logs deployment/gateway-update-agent -c client`.
The client holds no API-key signer or administrative key operations.

The signed program permits gateway metrics on port 9090, public gateway
checks and inference on port 9443, and router model-route status on port
30000. It rejects unlisted hosts, administrative key endpoints, worker drain
operations, and direct reload calls. A configuration change rolls the gateway
and router pods through their `checksum/config` annotation.
