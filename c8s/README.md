# Historical c8s deployment inputs

This directory preserves earlier per-environment policies, allowlists, and
verification inputs. Scripts and tests still use these files. They are not
the current production configuration or active policy.

Current releases select the exact c8s commit, node image, and core images
through [release/spec.yaml](../release/spec.yaml). The signed release records
their digests and node measurements. Read [release documentation](../release/README.md).

For a live endpoint, use [client verification](../docs/verification.md).
Production retains operator-managed policy. The policy returned by CDS can
change without a new node image and can differ from the signed initial policy.
Clients review and pin the exact active bytes.

The [historical generation procedure](historical-policy-generation.md) is
retained for audits of the older inputs only.
