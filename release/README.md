# Release

This directory is the one source of truth for the next software release. It
replaces the per-target files in `releases/` and `c8s/`. Those files stay
until the release tools no longer read them.

The release contains no target, placement, operator key, or mesh CA. The
private deployment repository holds the targets.

## Files

| File | Written by | Contents |
| --- | --- | --- |
| `spec.yaml` | A person | The version, the c8s release and its node image, the model identity, and the public hostnames |
| `values.yaml` | A person | The chart values of the release. Only release values, no deployment values |
| `allowlist-policy.json` | A person | The workloads, the c8s core images, and the inputs of the allowlist |
| `inputs/image-config.json` | `generate-release-allowlist.py --refresh-image-config` | The `ENV`, `ENTRYPOINT`, and `CMD` of every rendered image. Review the diff by hand |
| `inputs/cdi/nvidia-<driver>.json` | A person, from a reviewed record | The NVIDIA CDI environment variables and driver mounts of one driver version |
| `node-manifest.json` | `fetch-node-manifest.py` | The c8s `manifest.json` of the node image. It holds MRTD, RTMR1, and RTMR2 |
| `allowlist.json` | `generate-release-allowlist.py` | The exact c8s allowlist of the release, in canonical bytes |
| `accepted-lint-findings.json` | A reviewer | The `c8s allowlist lint --strict` findings that the release accepts, each with its reason and issue |

The release workflow builds the release manifest with
`build-release-manifest.py` at the tag commit. The manifest names that commit,
so it is not committed here. It must match
`contracts/release-manifest.schema.json`.

## Order

1. A person changes `spec.yaml` and `values.yaml` in a pull request. This
   specifies the release.
2. CI builds the container images from the pull request's commit. Put the
   new digests in `values.yaml`.
3. Run the release tools:

   ```sh
   python3 scripts/fetch-node-manifest.py
   python3 scripts/generate-release-allowlist.py --refresh-image-config
   python3 scripts/generate-release-allowlist.py --c8s <c8s CLI of the pinned commit>
   ```

   The allowlist generator refuses a value that no pinned input gives, such
   as a node IP address or a random pod name.
4. Merge the pull request. Tag the merge commit `vX.Y.Z`. The release
   workflow builds the manifest, signs it with Sigstore, and attaches the
   manifest, its signature, and the tag commit to the GitHub release.

To rebuild the manifest from the tagged tree:

```sh
python3 scripts/build-release-manifest.py \
  --source-commit "$(git rev-parse vX.Y.Z^{commit})" \
  --output /tmp/release-manifest.json
```

Its bytes must equal the signed `release-bundle.json` asset.

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

A release uses a version of three numbers, `vX.Y.Z`, with no release
candidate suffix. A fix is a new version.
