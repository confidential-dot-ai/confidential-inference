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

The gateway uses one internal HTTP service behind c8s TLS-LB. Public inference
requests and signed admin requests use that same entry path. The gateway reads
its API-key pepper from c8s application-secret memory. It stores API-key state
on an operator-supplied persistent volume.

`attestationReceipts.targets` defines the complete receipt set. Each entry
binds an operational target name, a c8s workload identity, and an internal
receipt-reader URL. The release bundle records the same target bindings.

The chart does not own public addresses, DNS, secret-manager paths, machine
names, or resource sizes. Keep those values in the operator repository.
