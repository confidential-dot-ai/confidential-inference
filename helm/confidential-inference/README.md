# Confidential Inference chart

This chart installs the gateway, router, inference workers, and optional
metrics components in a c8s Kubernetes cluster.

The default values form a small GPU-free simulator deployment. An operator
must supply an external values file for a real environment. The file must pin
every image by its Linux AMD64 digest.

```sh
helm lint helm/confidential-inference
helm template example helm/confidential-inference \
  --namespace example \
  --values /path/to/environment-values.yaml
```

A release publishes this chart as a package,
`ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:X.Y.Z`,
built once by the staging release of a source commit and bound by digest in
the signed release manifest (`chart.archiveSha256`), together with the
profile values files as release assets (`release/README.md`, "The release
build"). An installer that verifies those digests needs no checkout.

The gateway uses one internal HTTP service behind c8s TLS-LB. Public inference
requests and signed admin requests use that same entry path. The gateway reads
its API-key pepper from c8s application-secret memory. It stores API-key state
on an operator-supplied persistent volume.

`attestationReceipts.cds.url` names the CDS origin the gateway verifies for
its schema 3 policy metadata; leave it empty when the deployment procedure
sets the gateway's policy settings itself. The deployment supplies the two
policy documents (`attestationReceipts.cds.imagePolicy` and
`servedImagePolicy`, with `--set-file`); the chart mounts them next to the
release identity and writes their SHA-256 pins into it.

`attestationReceipts.targets` defines the complete receipt set. Each entry
binds an operational target name, a c8s workload identity, and an internal
receipt-reader URL. The release bundle records the same target bindings.

The chart does not own public addresses, DNS, secret-manager paths, machine
names, or resource sizes. Keep those values in the operator repository.
