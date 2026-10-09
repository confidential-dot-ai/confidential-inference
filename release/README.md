# Release

This directory is the one source of truth for the next production release. It
replaces the per-target files in `releases/` and `c8s/`. Those files stay
until the release tools no longer read them.

The release contains no target, placement, operator key, or mesh CA. The
private deployment repository holds the targets.

`release/profiles.json` declares the release profiles: the tag suffix, the
environment, the signing environment, and the layers of each profile. The
tools read the profile of a tag or a directory from it with
`scripts/release_profiles.py`.

`release/staging/` is the staging profile. It is a layer on top of this
directory. Its `spec.yaml` replaces only the model and the public hostnames,
and Helm applies its `values.yaml` after `release/values.yaml`. Staging uses
the CPU SGLang simulator and validates the encrypted model mount before the
simulator starts. It has its own allowlist policy and accepted lint findings.
It shares the node manifest and the image configuration. To move staging
ahead of production, set `c8s` in `release/staging/spec.yaml`; the node
manifest of that c8s release is then written to
`release/staging/node-manifest.json`.

The repository holds no digest of an image that it builds. The release build
takes each one from signed evidence, so a release needs no commit that pins
image digests. The release commit is the image source commit.

## Files

| File | Written by | Contents |
| --- | --- | --- |
| `spec.yaml` | A person, or `bump-c8s.py` for `c8s` | The c8s release with its node image and core images, the model identity, and the public hostnames. It is the one place that pins c8s. It names no version: the tag is the version |
| `values.yaml` | A person | The chart values of the release. Only release values, no deployment values. It names each repository image without a digest |
| `allowlist-policy.json` | A person | The workloads and the inputs of the allowlist. The c8s pins come from `spec.yaml` |
| `profiles.json` | A person | The release profiles and their layers |
| `inputs/image-config.json` | `generate-release-allowlist.py --refresh-image-config` | The `ENV`, `ENTRYPOINT`, and `CMD` of every image that a profile renders and this repository does not build. All profiles share it. Review the diff by hand |
| `inputs/cdi/nvidia-<driver>.json` | A person, from a reviewed record | The NVIDIA CDI environment variables and driver mounts of one driver version |
| `node-manifest.json` | `fetch-node-manifest.py` | The c8s `manifest.json` of the node image. It holds MRTD, RTMR1, and RTMR2 |
| `accepted-lint-findings.json` | A reviewer | The `c8s allowlist lint --strict` findings that the release accepts, each with its reason and issue |

## The release build

The release workflow runs `build-release-manifest.py` at the tag commit. It
writes three files, and the workflow attaches them to the GitHub release with
the signature, the tag commit, and the image publication evidence:

| Asset | Contents |
| --- | --- |
| `release-bundle.json` | The release manifest. The workflow signs it. It must match `contracts/release-manifest.schema.json` |
| `allowlist.json` | The exact c8s allowlist of the release, in canonical bytes. The manifest binds its SHA-256 as `allowlist.sha256`; `allowlist.path` names the profile, for example `release/staging/allowlist.json` |
| `release-values.yaml` | The repository image digests and `attestationReceipts.releaseId` (the tag) as a Helm values file. Apply it after the profile values files. The manifest binds its SHA-256 as `releaseValues.sha256`; `releaseValues.path` names the profile, for example `release/staging/release-values.yaml`. Each image in it is also in the manifest `images` |

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
   release. The build reads `base_ref` from the evidence (`source.baseRef`)
   and downloads `release-bundle.json` and `release-bundle.sigstore.json` of
   that GitHub release itself; the caller does not give them. The
   build verifies the base signature with the trust policy in
   `releases/trust/`, requires that the base manifest names the base tag and
   commit of the evidence, and requires that no build input of such an image
   changed since the base commit. A base release from the other profile is
   valid: the images do not depend on the profile. After a change to the
   trust policy, an older release does not verify; run `release-images` with
   a base release that the current policy signed, or with a commit base.

When `base_ref` is a commit, the evidence must name every repository image
that the chart renders.

The build then renders the chart with these digests, reads the
configuration of each repository image from the registry by digest, and
generates the allowlist with the c8s CLI built from the pinned c8s commit. It
binds the release source commit, the image publication evidence, the
allowlist digest, and the `release-values.yaml` digest into the manifest. A
consumer verifies each asset by its digest in the signed manifest.

`releaseValues` is optional in the schema because releases built before it
existed do not carry it, and they must still verify. The build always writes
it.

## Order

1. Merge the change to main. A release needs no other commit.
2. Run `release-images` on main with `publish` and `rebuild_audit` enabled and
   the newest release tag as `base_ref`. The workflow selects every changed
   repository image. This includes release images such as
   `maintenance-gateway` even when the application chart does not deploy
   them. It builds each selected image twice and requires equal platform
   digests. It then pushes the first audited OCI archive, so the pushed
   digest is the audited digest. The sglang archive is too large to pass
   between jobs, so sglang is built a third time and must give the same
   digest. Standard images do not wait for the sglang audit. The run writes
   one publication artifact, `release-image-publication-<commit>`. When no
   image changed since the newest image run, skip this step.
3. Tag the commit `vX.Y.Z` or `vX.Y.Z-staging`. The release workflow builds,
   signs, and publishes the release. The tag is the version, so no commit
   changes a version. A staging tag needs no production tag.

To build the release again from the tagged tree, give the same evidence and
a c8s CLI built from the pinned c8s commit. The build downloads the base
release that the evidence names:

```sh
python3 scripts/build-release-manifest.py \
  --tag vX.Y.Z-staging \
  --source-commit "$(git rev-parse vX.Y.Z-staging^{commit})" \
  --image-publication image-publication-manifest.json \
  --c8s /path/to/pinned/c8s \
  --output-dir /tmp/release \
  --check
```

Without `--check`, it writes the files to `--output-dir`. With `--check`, each
file there must equal a new build. The checked files are the release assets.
The repository is public, so downloading the base release needs no token;
the build sends `GH_TOKEN` to GitHub when it is set. `--download-dir` keeps
the downloaded files, and the build uses files already there after the same
signature and binding checks. Verifying the base release needs `cosign`;
reading the image configuration needs `crane` with read access to the
registry.

## Change the c8s release

Use one command to move every profile to a new c8s tag:

```sh
scripts/bump-c8s.py --tag vX.Y.Z --c8s-repo <clean c8s checkout at the tag>
```

For a signed beta, select the profile explicitly and use `--allow-beta`.
Production can use a beta when the deployment calls for it. The signature
check still requires the exact beta workflow and source commit.

It needs `crane`, Go, and read access to the c8s Go module. It changes the c8s
pins, the source lock, the node manifests, and the image config, and then
runs the release checks. The next release build generates the allowlist with
the new c8s CLI. The script stops when the attestation protocol files or the
NVIDIA inputs of the node image change. Do those steps by hand. Review the
full diff before you commit.

## The allowlist

Every application container gets exact environment and mount rules. The
generator combines five pinned sources: the image configuration, the chart
pod specification, the `kubernetes` Service variables and `HOSTNAME`, the
mounts that the c8s webhook adds, and the NVIDIA CDI record for GPU
containers. `c8s allowlist derive` of the pinned c8s release writes each
entry. The c8s core images get unrestricted entries, as the c8s bootstrap seed
names them. `tools/c8s-allowlist-canonical`, built against the pinned c8s
module, writes the canonical bytes. `c8s allowlist lint --strict` must pass,
except for the findings in `accepted-lint-findings.json`. The generator fails
on any other finding, and on a listed finding that no longer appears. Today
the file accepts 4 findings: the node image CDI mounts `/usr/bin/nvidia-smi`
and `/usr/bin/nvidia-persistenced` overlap the worker `PATH`
(c8s issue #713).

The `kubernetes` Service address is `10.53.0.1`. The node image measures the
service network `10.53.0.0/16`, so the address is the same on every cluster.

## Versions

A production release uses `vX.Y.Z`. A staging release uses `vX.Y.Z-staging`.
A fix is a new patch version. The tag selects the profile
(`release/profiles.json`), and the build takes the version from it: the
manifest `release.name` and the chart value `attestationReceipts.releaseId`
are the tag. Each profile is released on its own: `vX.Y.Z-staging` needs no
`vX.Y.Z`, and the two numbers can differ. Tags never move, so a failed
release uses the next patch number.
