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
its API-key pepper and its admin client configuration from c8s
application-secret memory. It keeps no state on disk: it pulls the API keys
from the admin (`gateway.admin` is its egress), is Ready only once it holds
them, and sends usage events back to the admin (`gateway.usage.enabled`).

The gateway no longer serves `/attestation` (clients verify the front door with
TEErminator; see [client verification](../../docs/verification.md)). The chart
still renders the gateway's former attestation inputs (`attestationReceipts`
except `attestationApiPort`,
`runtimeConfig.releaseBundle`, the `gateway-release-identity` ConfigMap); the
gateway ignores them. They go once production runs a release built from this
chart.

The chart does not own public addresses, DNS, secret-manager paths, machine
names, or resource sizes. Keep those values in the operator repository.

## Upgrade and rollback

`helm upgrade` and `helm rollback` roll the gateway and the router
(`RollingUpdate`, one extra pod each). The router Deployment (`sglang-router`)
and the gateway's router Service (`router-headless`) keep their names across
releases, so the old router serves until the new one is Ready. Set `runtimeConfig.releaseBundle` with `--set-file` to the
verified `release-bundle.json` so the release selection changes with the
release. The gateway and the router read their configuration files once at
start. A `checksum/config` pod annotation rolls them when the files change.
The gateway does not read the release selection, so a release that changes
neither its image nor its settings does not roll it.

The inference workers use `updateStrategy: OnDelete`. Helm updates their
StatefulSets, but a worker keeps its old pod until you delete it. Each worker
is its own StatefulSet with its own c8s workload and model volume, so neither
a StatefulSet `RollingUpdate` nor a PodDisruptionBudget keeps one worker
serving: both StatefulSets would roll at once, and a PodDisruptionBudget does
not apply to controller updates. Roll them one at a time:

```sh
for worker in inference-worker-0 inference-worker-1; do
  revision=$(kubectl -n "$NS" get statefulset "$worker" -o jsonpath='{.status.updateRevision}')
  kubectl -n "$NS" delete pod "$worker-0"
  # The new pod starts after the old one frees its GPUs; model load and
  # tuning take about 35 minutes.
  until [ "$(kubectl -n "$NS" get pod "$worker-0" \
      -o jsonpath='{.metadata.labels.controller-revision-hash}')" = "$revision" ]; do sleep 10; done
  kubectl -n "$NS" wait --for=condition=Ready "pod/$worker-0" --timeout=60m
  # Send one chat completion through the router before the next worker.
done
```
