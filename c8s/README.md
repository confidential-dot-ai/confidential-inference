# c8s policy and verification data

This directory contains the public c8s input schema and the canonical
allowlists that are needed to verify published workload receipts.

The production policy generator uses only the committed chart, production
values, image pins, and process commands in this repository. It does not read
the private deployment repository or any secret.

```sh
python3 scripts/regenerate-c8s-allowlist.py --help
```

The generator renders the public production Helm chart, writes a workload-only
bootstrap document, and passes it to the pinned c8s `render-allowlist` command.
The c8s canonicalizer then produces `allowlists/production.json`. It changes
that file only with `--apply`; it does not contact a cluster.

Build the exact c8s command and generate the policy as follows. Replace
`<c8s-checkout>` with a clean checkout of the commit in
`production-policy.json`.

```sh
commit=$(jq -r .c8s.sourceCommit c8s/production-policy.json)
test "$(git -C <c8s-checkout> rev-parse HEAD)" = "$commit"
make -C <c8s-checkout> VERSION="$commit" build-c8s
python3 scripts/regenerate-c8s-allowlist.py \
  --c8s <c8s-checkout>/build/c8s --apply
```

Review the exact images, commands, arguments, and secret paths before commit.

The allowlist identifies workload types. Multiple pod replicas can use one
workload type when they use the same image and exact process arguments.

The files under `allowlists/` are the authoritative release policies. A
private deployment must select one public Git commit, one file path, and the
file's canonical SHA-256 digest. It must not keep an editable copy. This rule
keeps deployment and public verification on the same policy bytes.

Production uses c8s static policy mode. The final allowlist is baked into the
measured node image. CDS seals the same policy digest into its mesh CA. The
running policy cannot change through an operator request. A policy update needs
a new public allowlist and a new measured node image.

Static mode still requires the configured `operatorPublicKey`. The deployment
tools require the matching public key file, verify its fingerprint, and pass it
to c8s with `--operator-keys`. This key authorizes CDS secret restoration only;
it does not update or replace the immutable static allowlist. The install input
must also keep its canonical file-backed allowlist.

The private deployment repository selects the public Git commit, allowlist
path, and canonical digest. It supplies infrastructure values and secrets, but
it does not keep another editable allowlist.

Integration-staging uses c8s static policy mode too, from release
`integration-staging-v11`. It seals `allowlists/integration-staging.json` into
its own measured node image, which is a different image from production's. The
two allowlists name different application images, so one image cannot serve
both environments. `images/control-plane-node/README.md` holds the
per-environment build table.

`regenerate-c8s-allowlist.py` also generates the integration-staging
allowlist. Pass `--config c8s/integration-staging-policy.json` to select it;
the script rejects any `--config` path outside this fixed pair. The staging
policy renders the same public Helm chart with `c8s/integration-staging-values.yaml`,
a values file that carries only the fields the chart needs for the staging
shape (simulator-mode inference, replica counts, and image digests) and no
secret material. It writes `allowlists/integration-staging.json`. Review this
file's exact commands, arguments, and secret paths the same way as production
before commit.
