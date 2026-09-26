# Historical release bundles

New releases do not use this directory as publication input.

From `v0.14.0`, the signed release workflow builds a manifest from `release/`.
A `vX.Y.Z-staging` tag uses `release/staging/`. A `vX.Y.Z` tag uses the
production profile at `release/`.

The checked-in JSON files are unsigned development artifacts that preserve old
release evidence. Historical signature verification still reads them. The release workflow does not accept
`integration-staging-v*`, `conf-inference-prod-v*`, or other old publication
tag families.

A published release has these immutable GitHub Release assets:

- `release-bundle.json`
- `release-bundle.sigstore.json`
- `release-tag-commit.txt`

The Sigstore bundle covers the exact release manifest bytes. The tag commit
file binds the assets to the source commit. Use
`scripts/verify-release-bundle-signature.py` to verify the signature with the
pinned trust policy.
