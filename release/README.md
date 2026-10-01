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
directory. Its `spec.yaml` replaces only the version and the public hostnames,
and Helm applies its `values.yaml` after `release/values.yaml`. Staging uses
the CPU SGLang simulator and validates the encrypted model mount before the
simulator starts. It has its own allowlist policy, accepted lint findings, and
allowlist. It shares the node manifest and the image configuration. To move
staging ahead of production, set `c8s` or `imageSourceCommit` in
`release/staging/spec.yaml`; the node manifest of that c8s release is then
written to `release/staging/node-manifest.json`.

## Files

| File | Written by | Contents |
| --- | --- | --- |
| `spec.yaml` | A person, or `bump-c8s.py` for `c8s` | The version, the c8s release with its node image and core images, the model identity, and the public hostnames. It is the one place that pins c8s |
| `values.yaml` | A person | The chart values of the release. Only release values, no deployment values |
| `allowlist-policy.json` | A person | The workloads and the inputs of the allowlist. The c8s pins come from `spec.yaml` |
| `profiles.json` | A person | The release profiles and their layers |
| `inputs/image-config.json` | `generate-release-allowlist.py --refresh-image-config` | The `ENV`, `ENTRYPOINT`, and `CMD` of every image that a profile renders. All profiles share it. Review the diff by hand |
| `inputs/cdi/nvidia-<driver>.json` | A person, from a reviewed record | The NVIDIA CDI environment variables and driver mounts of one driver version |
| `node-manifest.json` | `fetch-node-manifest.py` | The c8s `manifest.json` of the node image. It holds MRTD, RTMR1, and RTMR2 |
| `allowlist.json` | `generate-release-allowlist.py` | The exact c8s allowlist of the release, in canonical bytes |
| `accepted-lint-findings.json` | A reviewer | The `c8s allowlist lint --strict` findings that the release accepts, each with its reason and issue |

The release workflow builds the release manifest with
`build-release-manifest.py` at the tag commit. The manifest records that
release source commit, so it is not committed here. The profile also pins an
earlier `imageSourceCommit`. It consumes the machine-readable image
publication artifact from the successful `release-images` run for that
release version. The evidence records the exact source commit used to build
the images. It refuses an image whose pushed digest differs
from its deterministic rebuild digest or from the rendered release values.
It also refuses a release source commit that changes an image build input
after `imageSourceCommit`.
It must match
`contracts/release-manifest.schema.json`.

## Order

1. A person changes the image source and the version in `spec.yaml`. Merge
   that pull request.
2. After the image source changes are on main, run `release-images` once with
   `publish` and `rebuild_audit`
   enabled. Give it the normal `vX.Y.Z` version. The workflow selects every
   changed repository image. This includes release images such as
   `maintenance-gateway` even when the application chart does not deploy
   them. It rebuilds each selected image twice, publishes a third clean build, and
   requires all three platform digests to be equal. The one run writes two
   publication artifacts. One names `vX.Y.Z`. The other names
   `vX.Y.Z-staging`. Both artifacts record the same source commit and image
   digests.
3. Put the image run head commit in `imageSourceCommit` in `spec.yaml` and
   the published digests in `values.yaml`. Staging takes both from this
   layer. Run the release tools for each profile:

   ```sh
   python3 scripts/fetch-node-manifest.py
   python3 scripts/generate-release-allowlist.py --refresh-image-config
   python3 scripts/generate-release-allowlist.py --c8s <c8s CLI of the pinned commit>
   python3 scripts/generate-release-allowlist.py --release release/staging --c8s <c8s CLI of the pinned commit>
   ```

   The allowlist generator refuses a value that no pinned input gives, such
   as a node IP address or a random pod name.
4. Merge the release inputs. Tag that release commit `vX.Y.Z`. The release
   workflow gets the unique publication artifact for the version and exact
   `imageSourceCommit`. It checks that its digest references occur in the
   rendered release when that image is deployed. It permits a published
   release image, such as `maintenance-gateway`, that this application chart
   does not deploy. It proves that no image build input changed between the
   image source and tag commits. It then binds both commits and the digest
   evidence into the signed release manifest.
   The release workflow attaches both manifests, the signature, and the tag
   commit to the GitHub release.

To rebuild the manifest from the tagged tree:

```sh
python3 scripts/build-release-manifest.py \
  --source-commit "$(git rev-parse vX.Y.Z^{commit})" \
  --image-publication /path/to/image-publication-manifest.json \
  --output /tmp/release-manifest.json
```

Its bytes must equal the signed `release-bundle.json` asset.

## Change the c8s release

Use one command to move every profile to a new c8s tag:

```sh
scripts/bump-c8s.py --tag vX.Y.Z --c8s-repo <clean c8s checkout at the tag>
```

It needs `crane`, Go, and read access to the c8s Go module. It changes the c8s
pins, the source lock, the node manifests, the image configs, and the
allowlists, and then runs the release checks. It stops when the attestation
protocol files or the NVIDIA inputs of the node image change. Do those steps
by hand. Review the full diff before you commit.

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
A fix is a new patch version.
