# Release bundle tests

These tests cover the historical v0 verification format. Keep them to verify
old receipts. Do not use the v0 scripts to create a current release. Current
releases use `scripts/build-release-manifest.py` and
`.github/workflows/release-bundle.yml`.

The tool renders the production Helm chart. It records every controller container as one workload.

The tool combines each Helm command with the image configuration. Supply image configuration from the inspected image manifest.

Strict mode rejects dirty source, tagged images, placeholder digests, and missing trust inputs. Fixture mode permits placeholder digests for local tests.

Run the fixture test with this command:

```bash
python3 scripts/build-release-bundle.py \
  --fixture \
  --release-name v0-test \
  --image-configs tests/release-v0/image-configs.fixture.json \
  --output /tmp/v0-release.json
```

Do not use the fixture image configuration for a release. Strict mode rejects a file unless `fixtureOnly` equals `false`.

Inspect each published image. Supply its exact entrypoint and command in the production image configuration.

Normal release builds and publishes an image once. Run
`rebuild-release-images.py` as a separate final audit. It rebuilds each
product image once and compares the platform digest with the digest in the
release bundle.

Strict mode also needs the approved allowlist digest and the model dm-verity root. It writes no bundle until all checks pass.

The resulting JSON is not trusted until the tag workflow creates a real
Sigstore bundle. See `releases/README.md`. Public verification requires both
files and fails when the signature file is absent.
