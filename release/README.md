# Release

This directory is the one source of truth for the next software release. It
replaces the per-target files in `releases/` and `c8s/`. Those files stay
until the release tools no longer read them.

## Files

| File | Written by | Contents |
| --- | --- | --- |
| `spec.yaml` | A person | The version, the c8s release and its node image, the model identity, and the public hostnames |
| `allowlist.json` | The release tools | The exact c8s allowlist of the release |
| `node-manifest.json` | The release tools | The TDX measurements of the node image, in the format that TEErminator reads |
| `manifest.json` | The release tools | The release manifest. The release workflow signs it and attaches it to the GitHub release |

Only `spec.yaml` exists now. The release tools will generate the other files.

## Order

1. A person changes `spec.yaml` in a pull request. This specifies the release.
2. CI builds the container images from the pull request's commit.
3. The release tools generate `allowlist.json`, `node-manifest.json`, and
   `manifest.json`. The allowlist uses the container image digests and the
   model identity.
4. After the merge, the release tag on the merge commit starts the release
   workflow. It signs `manifest.json` and attaches the files to the GitHub
   release.

The release contains no target, placement, operator key, or mesh CA. The
private deployment repository holds the targets.

## Versions

A release uses a version of three numbers, `vX.Y.Z`, with no release
candidate suffix.
