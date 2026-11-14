# Confidential Inference chart

This chart installs the gateway, router, inference workers, and optional
metrics components in a C8s Kubernetes cluster.

The chart owns worker/router orchestration even when images are published by
confidential-sglang. It does not need a second integration chart or a host
Docker Compose launcher. The current aggregated and PD layouts have different
dependency and restart boundaries; preserve those requirements when changing
images. See the [inference serving interface](../../api/inference-serving.md)
and [image-build cleanup plan](../../docs/sglang-separation.md).

The default values form a small GPU-free simulator deployment. An operator
must supply an external values file for a real environment. The file must pin
every image by its Linux AMD64 digest. `scripts/render-allowlist.py` sets
`environment` from its `--environment` argument; an environment values file
must not set it.

```sh
helm lint helm/confidential-inference
helm template example helm/confidential-inference \
  --namespace example \
  --values /path/to/environment-values.yaml
```

A framework release publishes this chart as a package,
`ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:X.Y.Z`.
The signed release manifest binds it by digest (`chart.archiveSha256`). It
has no values files: each environment keeps its own
([release/README.md](../../release/README.md)).

The gateway uses one internal HTTP service behind the C8s router. Public inference
requests and signed admin requests use that same entry path. The gateway reads
its API-key pepper and its admin client configuration from C8s
application-secret memory. It keeps no state on disk: it pulls the API keys
from the admin (`gateway.admin` is its egress), is Ready only once it holds
them, and sends usage events back to the admin (`gateway.usage.enabled`).

The gateway no longer serves `/attestation` (clients verify the front door with
TEErminator; see [client verification](../../docs/verification.md)). The chart
renders nothing from its former attestation inputs (`attestationReceipts`
except `evidenceEgressCidrs`, `runtimeConfig.releaseBundle`). It
still accepts them, because `bin/deploy` sets them for every release it
deploys; they go once production runs a release built from this chart.

The gateway also pins `CI_FRAMEWORK_RELEASE` and
`CI_FRAMEWORK_RELEASE_BUNDLE_SHA256` from `frameworkRelease`, so the live
allowlist names the framework release. Only `scripts/render-allowlist.py`
sets `frameworkRelease`.

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
is its own StatefulSet with its own C8s workload and model volume, so neither
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

## Model download

A worker gets its model in one of two ways:

- The C8s model volume (the default): an encrypted volume that CDS opens for
  the pod (`inference.model.c8sVolumeSource`, the `confidential.ai/c8s-volumes`
  annotation).
- A download at each start (`inference.model.download.enabled`).

The plain model cache (`inference.model.cache`) is refused. The C8s v0.99.29
worker mounts its models disk (`/var/lib/models`) read-only, so `fetch-model`
cannot fill it.

With `inference.model.download`, the worker downloads the model at each start
to its writable `data` disk. That is the encrypted scratch disk of the
Confidential Cloud `c8s-worker` image (serial `confai-scratch`, at least 64
GiB). The guest encrypts it with a key for each boot, so it is empty after
each boot. The chart does this:

1. The pod gets a default-medium `emptyDir`, `model-download`. The kubelet
   places it under `/var/lib/kubelet`, on the scratch disk. The C8s node
   classifies the mount as encrypted storage, so an `emptyDir` allowlist rule
   admits it.
2. The container that verifies the model (`sglang`, the PD `engram-holder`, or
   `sglang-pair`) runs `fetch-model` first. It writes to
   `/mnt/c8s-data/model-download`. It checks each file against the byte
   manifest (`inference.model.download.manifest`, from the `model-manifest`
   ConfigMap). The argv pins the SHA-256 of the manifest. That SHA-256 must be
   the `mountVerification` pin of `revisionMetadata`, or the render fails.
3. Then `wait-for-model --plain-cache` checks every file again on a read-only
   mount of the same volume, at the model path
   (`volumeDirectory/<volume name>`). Then it starts SGLang. The model path is
   the same as with the C8s model volume, so the worker argv does not change.

A C8s v0.99.29 worker drops all outbound traffic of a pod, except to the
exits of its allowlist entry. The node gives a pod its exits only when all
its main containers run. Thus the download runs in a main container, not in
an init container. Each `inference.model.download.hosts` entry is one exit on
port 443. Its address goes into `hostAliases`, so no DNS answer can move it.
The first host is the endpoint. The other hosts are the hosts that it
redirects to. C8s accepts at most 8 exits, each a fixed address. The CDN of
Hugging Face has no fixed addresses, so use a model mirror at a fixed address.
Its TLS certificate must chain to a CA in the image. The deployment's
allowlist policy must declare `"egress": {"port": 443}` for each inference
workload. `scripts/render-allowlist.py` refuses a pod with `hostAliases` and
no declared egress. The `inference-worker-model-download` NetworkPolicy
admits the same addresses.

Limits:

- Each start downloads the whole model. A container restart keeps the
  `emptyDir`, and `fetch-model` keeps the files that match. A new pod or a
  reboot downloads all files again. The startup probe and the pair's
  `startupTimeoutSeconds` must include the download time.
- `sizeLimit` (512Gi by default) must hold the model. The kubelet evicts the
  pod above it. The scratch disk must hold the model and the other node state.
- The scratch disk encryption has no integrity protection. The checks before
  the start find a changed byte. After the start, the host can change blocks
  to random data without detection. With the C8s model volume, dm-verity
  checks every read.

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
  every worker reads those pages. The pod's C8s model volume is one mount,
  so the cache is shared. Separate pods would each open their own volume.
- `/dev/shm` is one Memory emptyDir for the pod.

Each worker's `args` are the launcher's exact argv. The chart checks that the
argv sets `--model-path` to the C8s volume path, `--host 0.0.0.0` (the router
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
escalation. The pod sets no host namespace. The C8s webhook refuses
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
layout; the render fails if it is enabled. With `inference.model.download`,
the holder (or, in a pair, the model gate of `sglang-pair`) downloads the
model before it verifies it, and every worker reads the same read-only
mount ("Model download"). With telemetry on, the collector
scrapes one job per PD worker (`inference-pd-<name>`, the worker's port: add
`--enable-metrics` to its args) besides the gateway, the router and
kube-state-metrics. The PD pod has no GPU exporter. SGLang serves
`/metrics` on the worker's serving port and has no separate metrics
listener, so the collector's NetworkPolicy rule admits it to that port and a
port rule cannot limit it to `/metrics`. The ordinary workers have the same
rule.

### Separate model disks for pairs

Each `inference.pd.paired.pairs` entry can set `modelVolumeName`. Without it,
the pair uses the first `inference.model.volumeNames` entry. With it, the
chart selects that disk and updates the model gate and both worker paths.
Other pairs retain their own disk selection. The key source is unchanged,
so an exact copy of the encrypted image can use the existing key grant.

The normal release selects `dsv41-a` for Pair A and `dsv41` for Pair B.
Attach both encrypted disks to the inference CVM, with distinct serials
`c8s-vol-dsv41-a` and `c8s-vol-dsv41`. Each pair can then reopen its disk
without a shared mapping. The signed release policy must include each exact
model mount path. This changes disk storage, not the transport within a pair.

### Gateway admission and routing

PD routing uses the ordinary worker profile's two-second health interval and
connection timeout, two-failure circuit breaker and ten-second breaker reset.
The health timeout remains five seconds, with three failed checks required.
These settings shorten failed-pair withdrawal without changing generation
timeouts or the existing retry budget. A health check can consume its full
timeout, so the interval is not a strict bound on withdrawal time.

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
