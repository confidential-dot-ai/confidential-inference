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
