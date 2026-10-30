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
renders nothing from its former attestation inputs (`attestationReceipts`
except `releaseId` and `attestationApiPort`, `runtimeConfig.releaseBundle`). It
still accepts them, because `bin/deploy` sets them for every release it
deploys; they go once production runs a release built from this chart.

The gateway's settings are one environment variable, `GATEWAY_RUNTIME_CONFIG`,
so the exact allowlist pins them. The gateway mounts only the admin signer
certificate and the admin API key hashes, which differ per deployment.

The chart does not own public addresses, DNS, secret-manager paths, machine
names, or resource sizes. Keep those values in the operator repository.

## Upgrade and rollback

`helm upgrade` and `helm rollback` roll the gateway and the router
(`RollingUpdate`, one extra pod each). The router Deployment (`sglang-router`)
and the gateway's router Service (`router-headless`) keep their names across
releases, so the old router serves until the new one is Ready. A settings
or routes change changes the gateway's or the router's pod template, so it
rolls that pod. A release that changes neither the gateway image nor its
settings does not roll the gateway.

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

## Prefill/decode layout

`inference.pd.enabled: true` replaces the aggregated `inference-worker-N`
StatefulSets with one StatefulSet, `inference-pd`, and puts the router in PD
mode. It is off by default. With it off, the chart renders exactly what it
rendered before the setting existed.

The `inference-pd` pod holds one container per prefill or decode worker and
an `engram-holder` container. They share one pod because the workers
depend on each other the way processes on one host do:

- Prefill writes KV cache straight into decode GPU memory through CUDA IPC
  handles (Mooncake intra-node NVLink). Containers of one pod share an IPC
  namespace; separate pods do not.
- The holder locks the checkpoint's Engram shards in the page cache, and
  every worker reads those pages. The pod's c8s model volume is one mount,
  so the cache is shared. Separate pods would each open their own volume.
- `/dev/shm` is one Memory emptyDir for the pod.

Each worker's `args` are the launcher's exact argv. The chart checks that the
argv sets `--model-path` to the c8s volume path, `--host 0.0.0.0` (the router
is another pod), `--port`, `--served-model-name` (`inference.model.name`),
`--disaggregation-mode`, and a prefill worker's
`--disaggregation-bootstrap-port`. A worker must not set
`CUDA_VISIBLE_DEVICES`: the device plugin assigns each container its GPUs,
numbered from 0. `tests/helm/test_pd_layout.py` compares the render with a
launcher plan and lists every difference.

The workers start one at a time, as the launcher starts them. Each one waits
for the holder's ready file and for every earlier worker's `/health`. The
holder first runs `wait-for-model`, so no worker starts before the model
files match the release.

Every container runs as uid 1001, with no capability and no privilege
escalation. The pod sets no host namespace. The c8s webhook refuses
`shareProcessNamespace`, so the chart does not set it. The layout needs these
things from the node, which the chart cannot grant:

- `RLIMIT_MEMLOCK` large enough for the holder's mlock of the Engram shards
  (about 189 GiB for DeepSeek-V4.1), inherited from the container runtime.
- Free order-9 pages for each confidential-compute `cuInit`. The launcher
  compacts host memory before each worker starts (`/proc/sys/vm`, root
  only). In Kubernetes the node image must provide proactive compaction.
- CUDA IPC between containers that each see only their own GPUs. This is
  not yet verified on a GPU node.

The chart sets `SGLANG_HOST_IP=127.0.0.1` for every PD worker. The prefill and
decode KV transfer ZMQ sockets then bind to loopback, and Mooncake advertises
loopback. Two listeners still bind every address, and only the NetworkPolicy
keeps other pods out: the KV bootstrap server shares the worker's `--host`
(`0.0.0.0`, which the router needs), and Mooncake's handshake listener always
binds `INADDR_ANY`.

The plain model cache (`inference.model.cache`) is not supported with this
layout; the render fails if it is enabled. With telemetry on, the collector
scrapes one job per PD worker (`inference-pd-<name>`, the worker's port: add
`--enable-metrics` to its args) besides the gateway, the router and
kube-state-metrics. The PD pod has no GPU exporter. SGLang serves
`/metrics` on the worker's serving port and has no separate metrics
listener, so the collector's NetworkPolicy rule admits it to that port and a
port rule cannot limit it to `/metrics`. The ordinary workers have the same
rule.

### Gateway admission and routing

The gateway admits at most `gateway.protection.inferenceConcurrency`
inference requests, holds up to `gateway.protection.inferenceQueue` more for
`queueTimeoutSeconds`, and answers the rest with 503 at once. The chart
default of 48 with no queue leaves most decode slots idle, so a PD deployment
must set `inferenceConcurrency` to at least the total `--max-running-requests`
of its decode workers. The render fails below that total. The example values
in `tests/helm/fixtures/dsv41-pd-values.yaml` set 128 with a queue of 64.
`perKeyConcurrency` (128 by default) still bounds one API key.

The router's `manual` policy (in `routerArgs`) keeps each `X-SMG-Routing-Key`
on one worker, so a conversation's next turn reuses the prefix cache of the
prefill worker that served its last turn. Without the header the router picks
a worker at random for each request. The gateway sends the header on every
request it can identify a conversation for (`services/gateway/src/routing_key.rs`):
an HMAC of the API key's record ID and either the caller's own
`X-SMG-Routing-Key` or a chat completion's opening messages. A legacy
completion without a caller key gets none. The secret is drawn at gateway
start, so a restart assigns every conversation a worker again, and more than
one gateway replica (`gateway.replicas`, 1 by default) would split a
conversation across the replicas' keys.
