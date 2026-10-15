# Historical production trust files

The PEM files in this directory belong to historical releases. They are not
the active production operator keys or mesh CA. Do not copy them into a new
verification configuration because their directory is named `production`.

Start with [client verification](../../../docs/verification.md). Select and
verify the signed release reported by your intended endpoint. Review the
exact active allowlist bytes, then configure TEErminator with the approved
node-image tuple, policy, front-door workload, and TLS name.

Schema 3 `/attestation` reports active operator public keys in
`c8s.operatorKeys`. The gateway reads them over a verified, certificate-pinned
CDS connection. Native C8s discovery supplies connection information; it is
not an independently trusted mesh CA. TEErminator verifies the connection
proof. Public `/operator-keys` is not the CDS endpoint.

The release-signing policy and Sigstore root under
[releases/trust](../../trust/README.md) have a different purpose and remain
release-signature inputs. Keep published release tags, signed bundles, and
historical PEM bytes unchanged. A deployment identity can change after a
cluster replacement; reusing an old key or CA can reject the new deployment.
