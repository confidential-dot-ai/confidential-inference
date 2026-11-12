# Release

This directory holds the inputs of the framework release and its signing
trust files. Generated assets are published on GitHub Releases. Historical
snapshots remain in Git history.

The framework release is the software: the image digests, the Helm chart,
the C8s release and its node image, and the tools that render an allowlist.
It holds no deployment value: no allowlist, no Helm values, no model, no
hostname, no address, no mesh CA. Each deployment keeps its own values and
allowlist policy, and renders its allowlist from a verified framework
release with `scripts/render-allowlist.py`.

The repository holds no digest of an image that it builds. The release build
takes each one from signed evidence, so a release needs no commit that pins
image digests. The release commit is the image source commit.

## Files

| File | Written by | Contents |
| --- | --- | --- |
| `spec.yaml` | A person, or `bump-c8s.py` for `c8s` and `images.c8sOperator` | The C8s release with its node image and core images, and every image that the chart can run, by chart image key. A repository image has no digest. It names no version: the tag is the version |
| `node-manifest.json` | `fetch-node-manifest.py` | The C8s `manifest.json` of the node image. It holds MRTD, RTMR1, and RTMR2 |
| `inputs/image-config.json` | `generate-release-allowlist.py --refresh-image-config` | The `ENV`, `ENTRYPOINT`, and `CMD` of every image in `spec.yaml` that this repository does not build, and of the C8s core images. Review the diff by hand |
| `inputs/cdi/nvidia-<driver>.json` | A person, from a reviewed record | The NVIDIA CDI environment variables and driver mounts of one driver version |
| `inputs/c8s-source-lock.json` | `bump-c8s.py` | The pinned C8s commits and source hashes. The signed manifest records its path and digest |
| `inputs/c8s-attestation-protocols/<commit>.json` | `bump-c8s.py` | The attestation protocol of each C8s commit. `check-c8s-protocol-lockstep.py` compares them with the source lock |
| `trust/` | A person | The release-signing policy and the Sigstore trusted root |

## The release build

A person pushes the tag `vX.Y.Z` on a main commit. The release workflow
(`.github/workflows/release-bundle.yml`) runs `build-release-manifest.py` at
the tag commit, signs the manifest, and attaches these files to the GitHub
release with the signature, the tag commit, and the image publication
evidence:

| Asset | Contents |
| --- | --- |
| `release-bundle.json` | The framework release manifest. The workflow signs it. It must match `api/release-manifest-v2.schema.json`. It names every image digest (`images`), the C8s release and core images (`c8s`), the node image and its measurements, the chart, and the source lock |
| `confidential-inference-X.Y.Z.tgz` | The chart package at version X.Y.Z (the tag without `v`). The manifest binds its SHA-256 as `chart.archiveSha256` and the registry reference the publish job pushes it to as `chart.reference` (`ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:X.Y.Z`). `chart.sha256` is the tree hash of `helm/confidential-inference` at the tag |

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

The operator of a deployment runs this from a checkout at the framework
release's source commit. It needs `helm`, `cosign`, `crane` with read access
to the registry, and a C8s CLI built from the pinned C8s commit:

```sh
python3 scripts/render-allowlist.py \
  --release release-bundle.json --signature release-bundle.sigstore.json \
  --values values.yaml --policy allowlist-policy.json \
  [--accepted-findings accepted-lint-findings.json] \
  --c8s /path/to/pinned/c8s --output-dir out
```

It verifies the release signature and that the checkout is the release
source. It refuses deployment values that set `images` or
`frameworkRelease`, because the framework release supplies them. The gateway
pins `frameworkRelease` as exact environment values, so the live allowlist
names the framework release and its bundle digest.
It renders the chart, refuses an image that the framework release does not
name, generates the allowlist, and runs `c8s allowlist lint --strict`. It
writes `allowlist.json`, `release-values.yaml` (apply it after the deployment
values files), and `render.json`, the SHA-256 of each input.

These checks help the operator. A client does not rely on them: it reads the
live allowlist and checks it against the signed framework release
([docs/verification.md](../docs/verification.md)).

The allowlist policy of a deployment lists its workloads (name and
controller), the chart release name, namespace, and Kubernetes version, the
`kubernetes` Service address, the CDI record, egress, and secret reads.
`tests/fixtures/deployments/` holds example deployments with example
addresses for the tests.

## Change the C8s release

```sh
scripts/bump-c8s.py --tag vX.Y.Z --c8s-repo <clean c8s checkout at the tag>
```

For a signed beta, add `--allow-beta`. The signature check still requires the
exact beta workflow and source commit.

It needs `crane`, Go, and read access to the C8s Go module. It changes the C8s
pins in `spec.yaml`, the source lock, the node manifest, the image config,
and the allowlist test fixture, and then runs the release checks. It stops
when the attestation protocol files or the NVIDIA inputs of the node image
change. Do those steps by hand. Review the full diff before you commit.

## The allowlist

Every application container gets exact environment and mount rules. The
generator combines five pinned sources: the image configuration, the chart
pod specification, the `kubernetes` Service variables and `HOSTNAME`, the
mounts that the C8s webhook adds, and the NVIDIA CDI record for GPU
containers. `c8s allowlist derive` of the pinned C8s release writes each
entry. The C8s core entries mirror the node image's bootstrap seed byte for
byte: CDS serves the uploaded allowlist as it is, so it must carry the seed.
The seed is the pinned C8s release's asset `allowlist-seed-<platform>.json`
(C8s #975; the platform of the node image tag, `-cdi` included). The generator
downloads it, verifies the release statement with cosign against the C8s
release workflow identity, and requires the asset's sha256 to be the one the
statement lists. A release from before the asset (C8s v0.59.1) has a record
in `inputs/c8s-seeds/<source commit>.json` instead.
`tools/c8s-allowlist-canonical`, built against the pinned C8s module, writes
the canonical bytes. `c8s allowlist lint --strict` must pass, except for the
findings that the deployment accepts. The generator fails on any other
finding, and on an accepted finding that no longer appears. A GPU worker
usually needs one: the node image CDI mounts `/usr/bin/nvidia-smi` and
`/usr/bin/nvidia-persistenced` overlap the worker `PATH` (C8s issue #713).

The `kubernetes` Service address is `10.53.0.1`. The node image measures the
service network `10.53.0.0/16`, so the address is the same on every cluster.
