# Release

This directory holds the inputs of the framework release and its signing
trust files. Generated assets are published on GitHub Releases. Historical
snapshots remain in Git history.

The framework release is the software: the image digests, the Helm chart,
the C8s release with its node and CDS guest images, and the tools that
render an allowlist. It holds no environment value: no allowlist, no Helm
values, no model, no hostname, no address, no mesh CA. Each environment keeps
its own values and allowlist policy in the deployment repository. Each
deployment renders its allowlist from a verified framework release and its
environment with `scripts/render-allowlist.py`. See the terms in
[README.md](../README.md#terms).

The repository holds no digest of an image that it builds. The release build
takes each one from signed evidence, so a release needs no commit that pins
image digests. The release commit is the image source commit.

## Files

| File | Written by | Contents |
| --- | --- | --- |
| `spec.yaml` | A person, or `bump-c8s.py` for `c8s` and `images.c8sOperator` | The C8s release with its node image, CDS guest image and core images, and every image that the chart can run, by chart image key. A repository image has no digest. It names no version: the tag is the version |
| `node-manifest.json` | `fetch-node-manifest.py` | The C8s `manifest.json` of the node image. It holds MRTD, RTMR1, and RTMR2 |
| `cds-manifest.json` | `fetch-node-manifest.py` | The C8s `manifest.json` of the CDS guest image. The release manifest binds its SHA-256 as `cdsImage.manifestSha256`, and the release publishes it as an asset; a deployment's `cds-pin.json` takes its launch digest from it |
| `inputs/image-config.json` | `generate-release-allowlist.py --refresh-image-config` | The `ENV`, `ENTRYPOINT`, and `CMD` of every image in `spec.yaml` that this repository does not build, and of the C8s core images. Review the diff by hand |
| `inputs/cdi/nvidia-<driver>.json` | A person, from a reviewed record | The NVIDIA CDI environment variables and driver mounts of one driver version |
| `inputs/c8s-source-lock.json` | `bump-c8s.py` | The pinned C8s commits and source hashes. The signed manifest records its path and digest |
| `inputs/c8s-attestation-protocols/<commit>.json` | `bump-c8s.py` | The attestation protocol of each C8s commit. `check-c8s-protocol-lockstep.py` compares them with the source lock |
| `inputs/c8s-seeds/<commit>.json` | `bump-c8s.py` | The allowlist seed of a pinned C8s commit and the inputs it was rendered with |
| `trust/` | A person | The release-signing policy and the Sigstore trusted root |

## The release build

A person pushes the tag `vX.Y.Z` on a main commit. The release workflow
(`.github/workflows/release-bundle.yml`) runs `build-release-manifest.py` at
the tag commit, signs the manifest, and attaches these files to the GitHub
release with the signature, the tag commit, and the image publication
evidence:

| Asset | Contents |
| --- | --- |
| `release-bundle.json` | The framework release manifest. The workflow signs it. It must match `api/release-manifest-v2.schema.json`. It names every image digest (`images`), the C8s release and core images (`c8s`), the node image and its measurements, the CDS guest image (`cdsImage`), the chart, and the source lock |
| `confidential-inference-X.Y.Z.tgz` | The chart package at version X.Y.Z (the tag without `v`). The manifest binds its SHA-256 as `chart.archiveSha256` and the registry reference the publish job pushes it to as `chart.reference` (`ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:X.Y.Z`). `chart.sha256` is the tree hash of `helm/confidential-inference` at the tag |
| `cds-manifest.json` | The C8s `manifest.json` of the pinned CDS guest image (`release/cds-manifest.json`). The manifest binds its SHA-256 as `cdsImage.manifestSha256` |

The build takes the image digests from two signed sources:

1. The image publication evidence. The workflow takes the artifact
   `release-image-publication-<commit>` of the nearest main commit at or
   before the tag commit that a successful `release-images` run published
   (`find-image-publication-run.py`). No image build input may change between
   that commit and the tag commit. Each image has one digest: the publish job
   pushes only the digest that the deterministic rebuild audit proved.
2. The signed manifest of the base release of that image run, when its
   `base_ref` is a release tag. The image run publishes only the images that
   changed after its base, so every other image keeps the digest of the base
   release. The build downloads and verifies that release itself, requires
   that it names the base tag and commit of the evidence, and requires that
   no build input of such an image changed since the base commit. A base
   release can be of the earlier format (`release-manifest/v1`, v0.14.0 to
   v0.16.x, including `-staging` tags).

When `base_ref` is a commit, the evidence must name every repository image
in `spec.yaml`.

The build writes the chart package itself, as a function of the tagged tree
and the version alone (sorted entries, fixed file metadata, no gzip name or
time), so a rebuild gives the same bytes. `helm package` is not reproducible,
so the build does not use it.

## Order

1. Merge the change to main. A release needs no other commit.
2. Run `release-images` on main with `publish` and `rebuild_audit` enabled and
   the newest release tag as `base_ref`. The workflow selects every changed
   repository image. It builds each selected image twice and requires equal
   platform digests. It then pushes the first audited OCI archive, so the
   pushed digest is the audited digest. The run writes one publication
   artifact, `release-image-publication-<commit>`. When no image changed
   since the newest image run, skip this step.
3. Tag the commit `vX.Y.Z` and push the tag. The release workflow builds,
   signs, and publishes the release. A fix is a new patch version. Tags never
   move, so a failed release uses the next patch number.

To build the release again from the tagged tree and compare it:

```sh
python3 scripts/build-release-manifest.py \
  --tag vX.Y.Z \
  --source-commit "$(git rev-parse vX.Y.Z^{commit})" \
  --image-publication image-publication-manifest.json \
  --output-dir /tmp/release \
  --check
```

With `--check`, each file in `--output-dir` must equal a new build.
Downloading the base release needs no token; the build sends `GH_TOKEN` to
GitHub when it is set. Verifying the base release needs `cosign`.

## Render a deployment allowlist

The operator runs this for each deployment, from a checkout at the framework
release's source commit. It needs `helm`, `cosign`, `crane` with read access
to the registry, and a C8s CLI built from the pinned C8s commit:

```sh
python3 scripts/render-allowlist.py \
  --release release-bundle.json --signature release-bundle.sigstore.json \
  --environment staging --values values.yaml --policy allowlist-policy.json \
  [--accepted-findings accepted-lint-findings.json] \
  --c8s /path/to/pinned/c8s --output-dir out
```

It verifies the release signature and that the checkout is the release
source. `--environment` is required: the environment name, for example
`staging` or `production` (lowercase letters, digits, and hyphens, at most 63
characters). The render sets the chart value `environment` to it. The gateway
gets it as `DEPLOYMENT_ENVIRONMENT`, and the chart permits
`stagingValidation` only when it is `staging`.

It refuses environment values files that set `images` or
`frameworkRelease`, because the framework release supplies them. It refuses
values files that set `environment`, because the render sets it from the
environment name. The gateway
pins `frameworkRelease` as exact environment values, so the live allowlist
names the framework release and its bundle digest.
It renders the chart, refuses an image that the framework release does not
name, generates the allowlist, and runs `c8s allowlist lint --strict`. It
writes `allowlist.json`, `release-values.yaml` (the image digests, the
framework release, and the environment name; apply it after the environment
values files), and `render.json` (the environment name and the SHA-256 of
each input).

These checks help the operator. A client does not rely on them: it reads the
live allowlist and checks it against the signed framework release
([docs/verification.md](../docs/verification.md)).

The allowlist policy of an environment lists its workloads (name and
controller), the chart release name, namespace, and Kubernetes version, the
`kubernetes` Service address, the CDI record, egress, and secret reads.
`tests/fixtures/deployments/` holds two example environments (`staging` and
`production`) with example addresses for the tests.

## Change the C8s release

```sh
scripts/bump-c8s.py --tag vX.Y.Z --c8s-repo <clean c8s checkout at the tag>
```

For a signed beta, add `--allow-beta`. The signature check still requires the
exact beta workflow and source commit.

It needs `crane`, Go, read access to the C8s Go module, and first on `PATH`
the Helm version that the worker image build pins (`HELM_VERSION` in its
`mkosi.sync`; v3.14.4 at C8s v0.99.29). `--c8s` gives a C8s CLI built from the
tag; without it the script builds one. It changes the C8s pins in `spec.yaml`,
the source lock, the seed record, the node and CDS manifests, the image
config, and the allowlist test fixture, and then runs the release checks.
The script stops when the attestation
protocol files or the NVIDIA inputs of the node image change. Do those steps
by hand. Review the full diff before you commit.

## Move a deployment to C8s v0.99.29

A release that pins C8s v0.99.29 runs only on v0.99.29 workers with a
standalone CDS VM. The old cluster's CDS state does not carry over: a new CDS
keeps its secrets in process memory, starts empty, and mints a new mesh CA
(C8s `docs/secrets.md`, `docs/cds-ha.md`). Keep the old cluster, its CDS and
its release serving until the new deployment passes every acceptance check.

The deployment has two kinds of input. Launch files never change while a VM
lives: `cds-config.yaml` for the CDS and `worker.yaml` for each worker, which
embeds the CDS pin and so the exact bytes of `cds-config.yaml`. The worker
documents the CDS admits are not in either file: operator-signed decrees in
the CDS log carry them, and a later `node-images` decree replaces the set
(C8s `docs/cds-ha.md`, `docs/launch-configuration.md`). Bring a deployment
of workers up in this order:

1. Write `cds-config.yaml` with `c8s cds config new --replica CDS_HOST
   --voters 1` and no `--node-pins`, so the launch file names no nodes.
   `CDS_HOST` is the CDS VM's DNS name or IPv4 address; name each replica
   for more than one VM, with an odd `--voters`. A CDS without `--replica`
   needs `--node-pins`, which cannot bind a worker document that embeds the
   configuration itself.
2. Boot the CDS VM from the release's `cdsImage` and that file.
3. Write `worker.yaml` with `c8s worker new` against the deployment's
   `cds-pin.json`.
4. Sign the Genesis decree as C8s `docs/cds-ha-runbooks.md` runbook 1
   describes, with `--image-manifest cds-manifest.json` from the release and
   `--worker-document worker.yaml --worker-image worker-image.json`, where
   `worker-image.json` holds the measurements of the release's node image
   (`c8s cds ha decree genesis`).
5. Admit every later or changed `worker.yaml` with a `node-images` decree on
   the set in force.

Hand traffic over only when all of these hold:

- The CDS VM runs the `cdsImage` that the release manifest pins, and its
  `cds-pin.json` launch digest comes from the release's `cds-manifest.json`
  asset, whose SHA-256 equals `cdsImage.manifestSha256` of the verified
  release manifest.
- Every client that verifies the deployment pins the worker's launch file
  besides the release's node image, as
  [verification.md](../docs/verification.md#releases-on-c8s-v09929) describes.
  Worker admission alone does not show that clients enforce the CDS image and
  configuration.
- The operator keys in its `cds-config.yaml` are the deployment's operator
  keys.
- Every application secret is written to the new CDS.
- Every encrypted volume key is written back from its escrow file with
  `c8s secrets put` (C8s `docs/volumes.md`). A volume without an escrow file
  cannot move; provision it again.
- Every client and gateway that pins a mesh CA pins the new CDS's mesh CA.
  Leaves issued under the old mesh CA are not trusted by the new deployment.

Accept the new deployment only after these checks pass on it:

1. A confidential workload starts, and its injected `c8s-cert` client gets a
   certificate from the standalone CDS.
2. The CDS admits each worker over TCP 1019, and the workers' pods start under
   the release allowlist.
3. A credential client whose `cds-pin.json` names another CDS launch digest
   is refused.
4. A worker launched with a `worker.yaml` that no entry of the decree in
   force binds is refused admission and gets no credentials. Read the set in
   force with `c8s cds ha decrees --config cds-config.yaml --cds-pin
   cds-pin.json --json` (its `node_pins`), not from `cds-config.yaml`.
5. The public attestation route verifies against the new release manifest
   and the RTMR[3] seed of the deployment's `worker.yaml`.
6. The same check with the seed of another `worker.yaml`, for example one
   that names another CDS configuration, fails.

Releases on C8s v0.99.0 and later carry `cdsImage`, which the release
manifest schema of earlier source commits refuses. Verify such a release with
`scripts/verify-release-bundle-signature.py` and
`api/release-manifest-v2.schema.json` from its own source commit or a later one.
Move every verifier, including deployment readiness checks, to that source
before you publish the release.

Roll back to the previous release and cluster when any check fails before
handover. After handover, rolling back needs the old CDS still running with
its secrets: once it stops, its secrets and mesh CA are gone, and a rollback is
a new deployment of the old release.

## The allowlist

Every application container gets exact environment and mount rules. The
generator combines five pinned sources: the image configuration, the chart
pod specification, the `kubernetes` Service variables and `HOSTNAME`, the
mounts that the C8s webhook adds, and the NVIDIA CDI record for GPU
containers. `c8s allowlist derive` of the pinned C8s release writes each
entry. The C8s core entries mirror the seed byte for byte: CDS serves the
uploaded allowlist as it is, so it must carry the seed. C8s publishes no seed
asset from v0.95.0. `bump-c8s.py` renders the seed with
`c8s node-image render` of the pinned commit, with the kubelet and Helm
versions of the worker image build, and records it in
`inputs/c8s-seeds/<source commit>.json`. The generator reads the record of
the pinned commit, and the framework manifest names its images
(`c8s.seedImages`). `render-allowlist.py` renders the seed again with the
pinned CLI and the record's inputs, with the record's Helm version first on
`PATH`, and fails unless the canonical render equals the record. `tools/c8s-allowlist-canonical`,
built against the pinned C8s module, writes the canonical bytes. `c8s allowlist lint --strict` must pass,
except for the findings that the deployment accepts. The generator fails on
any other finding, and on an accepted finding that no longer appears. A
deployment without accepted findings accepts no finding.

The allowlist pins the `kubernetes` Service address `10.53.0.1`. With C8s
v0.99.29 the control plane runs outside the TEE and the worker's launch file
sets the Service range (`kubernetes.serviceCIDR`). Both must give the
`kubernetes` Service `10.53.0.1`; the charts assume `10.53.0.0/16`.
