# Release trust files

`release-signing-policy.json` defines the one accepted GitHub Actions signer.
It also pins the Cosign version and the public Sigstore trusted-root file.

The trusted root contains only public Fulcio, Rekor, certificate-log, and
timestamp-authority material. It came from the Sigstore public-good TUF
repository on 2026-09-01. Cosign v3.1.2 created it with this command:

```sh
cosign trusted-root create \
  --with-default-services \
  --out sigstore-public-good-trusted-root.json
```

Review a new root as a trust-policy change. Update its SHA-256 in the policy.
Then create new release bundles that pin the new policy digest. Do not change
an old signed release or its trust inputs.

## File locations and verification

The release builder writes `release/trust/release-signing-policy.json` into
new manifests as the policy reference. The Python verifier reads this fixed
local file and passes its signer rules and the trusted root to Cosign. Cosign
checks the signature; it does not search the repository for trust files.

The policy and root moved here without a byte change. Published releases,
including `v0.16.2`, still bind the original policy digest. That policy names
the root under `releases/trust/`. The verifier maps only the two known old
file references to these local files, and still checks both digests. It never
loads a policy from a path chosen by a downloaded manifest.

The policy is the source of the accepted publisher identity. Python checks
that its repository, workflow, and certificate identity agree, then requires
the release source to match that publisher. Changing this file is a trust
decision, not an ordinary deployment setting.
