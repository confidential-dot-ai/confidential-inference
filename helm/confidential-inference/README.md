# Confidential Inference chart

This chart installs the gateway, router, inference workers, and optional
metrics components in a C8s Kubernetes cluster.

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

The chart has no operator-key values. Clients pin the reviewed policy and
route digest instead.

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

The inference workers use `updateStrategy: OnDelete`. One StatefulSet,
`inference-worker`, runs every worker: pods `inference-worker-0` to
`inference-worker-<replicas - 1>`. Helm updates the StatefulSet, but a worker
keeps its old pod until you delete it. Roll the workers one at a time, so
that the others keep serving:

```sh
revision=$(kubectl -n "$NS" get statefulset inference-worker -o jsonpath='{.status.updateRevision}')
for index in $(seq 0 $(( $(kubectl -n "$NS" get statefulset inference-worker -o jsonpath='{.spec.replicas}') - 1 ))); do
  pod="inference-worker-$index"
  kubectl -n "$NS" delete pod "$pod"
  # The new pod starts after the old one frees its GPUs; a large model takes
  # about 35 minutes to load and tune.
  until [ "$(kubectl -n "$NS" get pod "$pod" \
      -o jsonpath='{.metadata.labels.controller-revision-hash}')" = "$revision" ]; do sleep 10; done
  kubectl -n "$NS" wait --for=condition=Ready "pod/$pod" --timeout=60m
  # Send one chat completion through the router before the next worker.
done
```

## Workers and the router

All worker pods are one C8s workload: the `confidential.ai/cw` annotation
names the allowlist entry `inference.attestedWorkload` (default
`inference-worker`), and every pod claims it. The pods differ only in their
name, so the entry requires `HOSTNAME` and admits any value
(`scripts/generate-release-allowlist.py`). This is so for every value of
`inference.replicas`, 1 included: a scale of the StatefulSet at runtime (for
example from 1 to 2 pods) needs no new allowlist. The deployment's allowlist policy
has one item for them: `{"name": "inference-worker", "controller":
"StatefulSet/inference-worker"}`.

The scheduler places a worker that downloads its model
(`inference.model.download`): on a node with free GPUs and, when it is set,
with the labels of `scheduling.inferenceNodeSelector`. A worker that reads a
C8s model volume runs only on the nodes of `scheduling.inferenceNodeNames`
(or on `scheduling.inferenceNodeName`), because the volume is node-local.
Every worker uses the first name of `inference.model.volumeNames`.

The router finds the workers with Kubernetes service discovery. It watches
the pods of its namespace with the labels
`app.kubernetes.io/component=inference-worker` and
`confidential.ai/traffic-eligible=true`. It adds each pod that is Running and
Ready (readiness is a 1-token generation, `/health_generate`) at
`<pod IP>:<inference.port>`, and removes a pod when it is deleted. Its own
health checks (`/health_generate`, 3 failures) stop traffic to a listed
worker whose scheduler does not answer, until it answers again.

A C8s mesh member cannot reach the API server through the `kubernetes`
Service: the Service address is in a cluster range, so the mesh captures the
connection. The router dials the API server's own address,
`router.discovery.apiServer.address` (default: a documentation address that
reaches no API server). That address is the router's one allowlist exit, so
the deployment's allowlist policy must declare `"egress": {"port": <port>}`
for `Deployment/sglang-router`, with `router.discovery.apiServer.port`.

An environment that sets the address at deploy time (after the release
render of the allowlist, for example when the control plane is made with the
cluster) sets `router.discovery.apiServer.cidrs` instead: a list of the IPv4
ranges the address can be in, for example `["10.48.64.0/18"]`. Each range is
`a.b.c.d/n` with `n` from 16 to 32 (C8s refuses an exit broader than /16),
with no host bits, at most 8. Each range is then one allowlist exit on the
port, in place of the exact address; the chart writes the list to the
Deployment annotation `inference.confidential.ai/egress-cidrs`, which the
allowlist generator reads. The pod still dials
`router.discovery.apiServer.address` (its `hostAliases` entry and
kubeconfig), which the deploy sets. The chart refuses an address outside
every range, except a documentation address (192.0.2.0/24, the default),
which means "not known yet". The router's node must not be in a range, and
neither must the cluster's pod and Service ranges: C8s refuses an exit to the
node's own address or into the cluster. With an empty list (the default) the
exit is the exact address. The `router-paths` NetworkPolicy names only the
port in both cases: the API server is a host identity to Cilium, and C8s
limits the address.

The router reads a kubeconfig, its service account token and the cluster CA
from one projected volume below `/mnt/c8s-data/kubernetes`, and checks the
API server certificate for `router.discovery.apiServer.serverName`
(`kubernetes.default.svc`). The Role `sglang-router-pods` lets it get, list
and watch pods in its namespace only.

The API server is outside the trust boundary, as DNS is: it only selects
the worker addresses. The mesh authenticates every worker connection.

## Model download

No model is in an image. A worker gets its model in one of two ways:

- The C8s model volume (the default): an encrypted volume that CDS opens for
  the pod (`inference.model.c8sVolumeSource`, the `confidential.ai/c8s-volumes`
  annotation).
- A download at each start from a model server
  (`inference.model.download.enabled`).

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
2. The container that verifies the model (`sglang`) runs `fetch-model` first. It writes to
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
the model server port (443 by default; see "Plain HTTP model server"). Its
address goes into `hostAliases`, so no DNS answer can move it.
The first host is the endpoint. The other hosts are the hosts that it
redirects to. C8s accepts at most 8 exits, each a fixed address. The CDN of
Hugging Face has no fixed addresses, so use a model mirror at a fixed address.
With `https`, its TLS certificate must chain to a CA in the image. The
deployment's allowlist policy must declare `"egress": {"port": <port>}` for
each inference workload. `scripts/render-allowlist.py` refuses a pod with
`hostAliases` and no declared egress. The `inference-worker-model-download` NetworkPolicy
admits the same addresses.

Limits:

- Each start downloads the whole model. A container restart keeps the
  `emptyDir`, and `fetch-model` keeps the files that match. A new pod or a
  reboot downloads all files again. The startup probe must include the
  download time.
- `sizeLimit` (512Gi by default) must hold the model. The kubelet evicts the
  pod above it. The scratch disk must hold the model and the other node state.
- The scratch disk encryption has no integrity protection. The checks before
  the start find a changed byte. After the start, the host can change blocks
  to random data without detection. With the C8s model volume, dm-verity
  checks every read.

## Plain HTTP model server

`inference.model.download.scheme` is `https` (the default) or `http`.
`inference.model.download.port` is the port of the model server; 0 (the
default) means 443 for `https` and 80 for `http`. The port is also the port
of the `inference-worker-model-download` NetworkPolicy and of the allowlist
exits, so the allowlist policy must declare `"egress": {"port": <port>}` for
each inference workload.

Plain HTTP on an internal address is safe for the model bytes:

- `fetch-model` checks every downloaded file against the byte manifest. The
  release pins the SHA-256 of the manifest (`mountVerification`), and the
  render fails if the manifest does not match the pin.
- `wait-for-model --plain-cache` checks every file again, on a read-only
  mount, before the server starts. A changed, missing or extra byte stops the
  worker.
- The weights are public, so plain HTTP discloses nothing secret. An observer
  on the path can see which model the workers download.

TLS adds no integrity that the manifest does not give. Without TLS, a
network attacker can still stop the download (as with TLS), but cannot make
a worker serve other bytes.

## Worker image

Every worker runs the one engine image, `images.sglangConfidential`
(`images/sglang-confidential`, plain upstream SGLang). The image holds no
model. The values choose the model, its parsers and its source. A model is a
recipe in values only, for example:

- `tests/fixtures/deployments/production-values.yaml`: DeepSeek-V4.1 on a C8s
  model volume.
- `tests/fixtures/deployments/qwen35-staging-values.yaml`: Qwen3.5-0.8B,
  two workers with one GPU each, downloaded over plain HTTP from a model
  server, pinned by its byte manifest
  (`tests/fixtures/deployments/qwen35-0.8b-model-manifest.json`), with the
  Qwen parsers.

`inference.workerImage`, `inference.model.source` and
`inference.model.imagePath` were removed; the render fails if they are set.

## Prefill/decode layout (removed)

The chart runs aggregated workers only (`inference-worker`, one complete
SGLang server each, behind the router). The prefill/decode layout
(`inference-pd`) and its pairs (`sglang-pair`) were removed: neither the
production recipe nor the staging recipe uses them. `inference.pd.enabled`
stays in the schema so that existing environment values still render; only
`false` is accepted.

## Gateway admission

The gateway admits at most `gateway.protection.inferenceConcurrency`
inference requests, holds up to `gateway.protection.inferenceQueue` more for
`queueTimeoutSeconds`, and answers the rest with 429 `inference_capacity` at
once. The chart default is 48 with no queue.
`perKeyConcurrency` (128 by default) still bounds one API key.

## Long requests

For 1M-token requests, size the gateway, the router and the workers from the
GPU capacity with [docs/long-context-sizing.md](../../docs/long-context-sizing.md):

- `gateway.protection.bodyMemoryBytes` bounds the memory of all request
  bodies together (`docs/request-body-limit.md`).
- `gateway.protection.firstTokenTimeoutSeconds` (default 3600) is the wait
  for the first chunk: the queue and the prefill.
  `upstreamTimeoutSeconds` (default 14400) is the whole request.
- `router.requestTimeoutSeconds` (default 14460) must be at least
  `upstreamTimeoutSeconds`.
- `router.workerWaitSeconds` (default 30) is how long the router holds a
  request while no worker is available (failed health checks, or the only
  worker restarting) before 503 `no_available_workers`. It applies only to
  this repository's patched router (`images.sglangRouter`); with
  `router.image: confidentialSglangRouter` the flag is not rendered.
- `router.maxConcurrentRequests` (default 0, off) must be at least
  `inference.replicas` x the worker's `--max-running-requests`.
- `inference.contextLength` and `inference.maxRunningRequests` (default 0:
  the model's own value) set the worker flags.

The gateway sends an `X-SMG-Routing-Key` header on every request it can
identify a conversation for (`services/gateway/src/routing_key.rs`). The
default `router.policy: cache_aware` does not read it: it picks a worker by
prefix match and load. `router.policy: consistent_hashing` hashes it onto a
ring of the worker URLs, so every router with the same workers sends a
conversation to the same worker. `router.consistentHashingLoadFactor`
(default 1.25, 0 = off) caps how far one worker can run ahead of the others
(`images/sglang-router`, bounded loads); like `router.workerWaitSeconds`, it
renders only for this repository's patched router (`images.sglangRouter`).
