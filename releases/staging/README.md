# Staging release bundles

This directory holds signed release inputs for the `staging` environment,
the same way `releases/conf-inference-prod/` and `releases/production/` do.
See `releases/README.md` for the release and signing process.

Staging is a fresh cluster on c8s v0.21.2, not an upgrade of the previous
staging cluster, so its release counter starts at `staging-v1`. No `release-bundle.json` is committed here yet. The release
flow builds and commits one with `scripts/build-release-bundle.py`
(`--environment staging`), using the committed `c8s/staging-policy.json`,
`c8s/staging-values.yaml`, and the generated `c8s/allowlists/staging.json`
as its inputs, once the real operator key, mesh CA, and gateway image for
the new cluster exist.
