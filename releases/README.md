# Signed release bundles

The JSON files in this directory are release inputs. They are not trusted by
themselves. A public release needs these two GitHub Release assets:

- `release-bundle.json`
- `release-bundle.sigstore.json`
- `release-tag-commit.txt`

The second file contains a short-lived Fulcio certificate, the keyless
signature, and the Rekor transparency-log proof. The signature covers the
exact bytes of the first file.

The checked-in bundles are unsigned development artifacts. Do not call them
signed until the tag workflow
publishes a matching real Sigstore bundle. The same protected workflow can
sign one production bundle or one integration-staging bundle. It does not
deploy either environment.

## Create a signed release

1. Build the selected environment release bundle with strict inputs.
2. Set `release.name` to the intended protected tag:
   - Production: `v0.13.0`.
   - Integration staging: `integration-staging-v1`.
3. Commit the bundle and all public release inputs to `main`.
4. Make sure that the recorded source commit is an ancestor of the tag.
5. Create and push the exact release tag.
6. Approve the protected GitHub Environment job for the selected environment:
   `signed-release-production` or `signed-release-integration-staging`.

`.github/workflows/release-bundle.yml` then performs these actions:

1. It installs the schema validator from a complete SHA-256-locked dependency
   file.
2. It validates the complete release schema, policy digest, source repository,
   release name, tag, and source ancestry.
3. It installs Cosign v3.1.2 through a commit-pinned installer.
4. It gets a GitHub Actions OIDC identity and creates a keyless signature.
5. It writes the certificate and transparency proof to the Sigstore bundle.
6. It verifies the signature offline with the source-controlled trusted root.
7. A second job, which has no OIDC permission, confirms that the remote tag
   still names the signed commit. It then creates a new GitHub Release and
   uploads all three files.

The signing job can read repository contents and request an OIDC token. It
cannot write repository contents. The publishing job can create the GitHub
Release. It cannot request an OIDC token.

The workflow refuses to replace assets in an existing GitHub Release. Protect
release tags against deletion and replacement. Require different reviewers for
the `signed-release-production` and `signed-release-integration-staging`
environments when the environments have different trust levels.

The workflow selects the bundle from the tag. A tag that starts with `v` and a
digit signs only `releases/production/release-bundle.json`. A tag that starts
with `integration-staging-v` and a digit signs only
`releases/integration-staging/release-bundle.json`. The preparation program
checks this tag-to-environment binding again. A staging tag cannot sign the
production bundle, and a production tag cannot sign the staging bundle.

## Verify a release without network access

Check out the same public repository tag. Install the exact Cosign version in
that tag's signing policy. Download both release assets before you disconnect
the network. Then run:

```sh
python3 scripts/verify-release-bundle-signature.py \
  --bundle /path/to/release-bundle.json \
  --signature-bundle /path/to/release-bundle.sigstore.json \
  --cosign /path/to/cosign
```

The verifier uses
`releases/trust/sigstore-public-good-trusted-root.json`. It blocks network
access for Cosign. It verifies these facts:

- The signature covers the exact release-bundle bytes.
- The certificate issuer is GitHub Actions.
- The certificate identity names this repository, this workflow, and this tag.
- The certificate claims contain the expected repository, ref, workflow name,
  and push trigger.
- The Rekor entry has a valid offline inclusion proof.
- The Fulcio and Rekor trust material matches the pinned trusted root.

## Trust limits

The signature proves that the named workflow signed these bytes. It does not
prove that the live cluster runs this release. The public attestation verifier
checks that separate fact.

GitHub tag protection and environment approval are part of the release
authority. The repository cannot enforce those account settings. Configure
separate protected environments for production and integration staging.
The verifier also trusts the local Cosign executable. It checks its version and
source commit, but the user must install it from a trusted source.

The trusted root is a frozen public Sigstore root. A root rotation requires a
reviewed update to the trusted-root file, its policy digest, and each new
release bundle. Never rewrite a prior signed release.

The bundles listed in `releases/pre-history-releases.json` were built from a
source history that is not in this repository; the next release is the first
that rebuilds from here.
