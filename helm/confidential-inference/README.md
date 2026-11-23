# Confidential Inference chart

This chart installs the gateway, router, inference workers, and optional
metrics components in a C8s Kubernetes cluster.

Set `c8s.ta.cidrs` to the Trust Authority addresses and `c8s.ta.port` to its TCP port (default 8443).
Values under `c8s.ta` override matching fields under `c8s.cds`, which holds the defaults.

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
name, and the chart sets `HOSTNAME` to `inference-worker` in each, so the
entry names an exact value for every variable. C8s requires that of an
entry that declares egress. This is so for every value of
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

- The C8s model volume (the default): an encrypted volume that the Trust Authority opens for
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

## Prefill/decode pairs (`inference.layout: pair`)

A pair recipe (`recipes/README.md`) sets `inference.layout: pair` and
`inference.pair`. Each replica is then two pods:

- `inference-pair-<i>`, a pod of the StatefulSet `inference-pair` (headless
  Service `inference-pairs`). Its one container runs `sglang-pair` from the
  engine image: the model gate (fetch-model when `inference.model.download`
  is on, wait-for-model, then the Engram holder, which locks about 198 GiB of
  host memory), then the prefill and the decode worker of the recipe's launch
  plan, one after the other, each with the cold-path warmup. Prefill writes KV
  into decode's GPU memory over NVLink. CUDA IPC needs one process namespace
  that sees both workers' GPUs; C8s gives that only inside one container. The
  startup, readiness and liveness probes read sglang-pair's status port.
  Every pair pod claims one allowlist entry (`inference.pair.attestedWorkload`).
- `pd-router-<i>`, a Deployment of one router pod (router image). It sends
  each request to `inference-pair-<i>`'s prefill and decode by their
  headless-Service names, with the plan's router arguments. Decode reaches
  prefill's KV bootstrap server on loopback inside the pair, whatever address
  the router names. The PD routers differ in the pair they reach, so each has
  its own allowlist entry, `<inference.pair.pdRouter.attestedWorkloadPrefix>-<i>`:
  the deployment's allowlist policy lists one per replica. A PD router has no
  exit and no Kubernetes API access.

The cache-aware router (`sglang-router`) discovers the Ready PD router pods
(label `app.kubernetes.io/component=pd-router`) and routes between them; a PD
router is Ready while its pair's prefill and decode are. Only that router
talks to the Kubernetes API, at the deploy-time address of
`router.discovery.apiServer`.

The environment sets `inference.replicas`, `inference.pair.resources` (the
defaults are conservative, not measured), the model server, and the router's
API server. `inference.pd.enabled` stays in the schema so that existing
environment values still render; only `false` is accepted.

### Kernel cache seed

A pair compiles its kernels into the plan's cache tree,
`paths.kernel_cache_dir` of the launch plan (`/tmp/dsv41/kernel-cache` for
dsv41-262k). The plan's worker env puts every compiler cache under it:
`SGLANG_CACHE_DIR` is the root, and `CUDA_CACHE_PATH` (`nv`),
`FLASHINFER_WORKSPACE_BASE` (`flashinfer`), `TORCHINDUCTOR_CACHE_DIR`
(`inductor`) and `TRITON_CACHE_DIR` (`triton`) are below it. The tree lives in
the pod's `/tmp` emptyDir, so every new pod starts cold: dsv41-262k on a 4x
B200 takes about 26 minutes to `/readyz` cold and about 9 minutes warm. The
warm tree is about 145 MB.

With `inference.pair.kernelCache.seed.enabled`, the pair fetches a warm tree
from the model mirror before the model gate. fetch-model reads each file at
`<repository>/resolve/<revision>/<path>` from the `inference.model.download`
hosts in order. It checks every file's SHA-256 and size against the seed
manifest, whose own SHA-256 is in the pair's argv and so in its allowlist
entry. A file that does not match is not written. When the whole seed is in
place, fetch-model also removes every file under the directory that the
manifest does not list (after a container restart, what the last run compiled
beyond the seed). If no host gives the whole seed, the gate goes on with the
files it verified and the workers compile the rest, as without a seed.

The seed is the whole tree. `inference.pair.kernelCache.planDirectory` is
rendered by `scripts/recipe-values.py` from the plan's `paths.kernel_cache_dir`.
With the seed on, the chart refuses to render if `planDirectory` is not the
workers' `SGLANG_CACHE_DIR`, or if one of the cache variables above points
outside it. Make the seed from the whole tree: a seed with only some of the
subdirectories (for example only `triton`) still fetches and verifies, but
the other caches start cold and the warmup takes nearly as long as without a
seed. The tree includes FlashInfer's run-time `cubins` download
(`flashinfer/.cache/flashinfer/cubins`); the seed carries it under the same
pin.

#### What the seed is trusted for

Seeded kernels are compiled outside the TEE, on a bring-up host. They are
code: Triton cubins, Inductor modules and shared objects, CUDA binaries.
Nothing measures how they were built. They are trusted only because their
exact bytes are pinned. The manifest lists every file's SHA-256 and size, and
the manifest's own SHA-256 is in the pair's argv, so in its C8s allowlist entry
(the attested workload). That is the same trust as the model weights: the
release pins the bytes, not where they came from. A verifier who accepts the
allowlist entry accepts those bytes, and so trusts whoever made the seed. The
release signature and the TEE measurements do not cover the seed; the
manifest pin does.

A host or mirror that changes a seed byte cannot make the pair run it:
fetch-model refuses the file, and the worker compiles that kernel itself. A
host that withholds the seed only makes the start cold. A wrong seed that
matches its manifest (for example one made from another image) is refused at
render time by the revision check below, not at run time.

Without the seed, the workers compile at start inside the TEE with the
compilers of the measured image; those kernels are not pinned either, but they
come from the measured code. The seed trades that for pinned bytes made
outside.

`jit_compile` keeps its meaning. In a pair it comes from the workers' Triton
compile listener (confidential-sglang `python/sglang/srt/utils/triton_load_watch.py`
and `pair_progress.compile_event`): one event per Triton compile that is not
a cache hit, forwarded by sglang-pair once that worker is ready. It is not a
scan of the cache directory against a baseline (the CompileWatcher of
`images/sglang-confidential/wait_for_model.py` is the worker layout's; the
pair does not forward the gate's `jit_compile`). So:

- a seeded kernel is a cache hit: it is part of the pinned startup state and
  is never reported as a run-time compile, before or after `worker_ready`;
- a kernel that the seed lacks, or one recompiled over a seeded file after
  `worker_ready`, is a compile and is reported as before.

The seed's own fetch shows in the pair's events: the first
`model_fetch_started` (role `pair`) is the seed's, with its file count and
size, then its `model_fetch_complete` (files downloaded and kept) or
`model_fetch_failed`, before the model's fetch. A `model_fetch_failed` before the model's fetch is a cold start, not a
failed pair.

#### Platform, owner and lifetime

A seed is tied to one engine image, one plan, one GPU model and one driver.
CUDA, Triton and FlashInfer binaries are built for the bring-up host's GPU
architecture and driver, and the cache keys include them. The manifest's
revision is `sha256-<engine image digest>-<plan>`, and the chart refuses to
render a seed of another engine image or plan. The plan fixes the GPU model
(its layout's `target.gpu_models`, B200 for dsv41-262k), so make the seed on
that GPU. The revision does not name the driver: a seed made on another
driver still renders, and its Triton and Inductor binaries load as they were
built (only the CUDA driver's own PTX cache is keyed by driver and misses).
So make the seed on the driver of the release's C8s node image, and make a
new one when that driver changes.

A new engine image starts cold: its seed is refused at render time, so turn
the seed off or make a new one in the same release change. The engineer who
pins the engine image (the release PR) makes the seed, when one of these
changes:

- the engine image digest (a confidential-sglang release record);
- the launch plan, or its target GPU;
- the node image's NVIDIA driver (a C8s pin change).

Retire a seed when its image or plan leaves the release; remove its files from
the mirror once no deployed release names its revision. After a deploy,
check the seed: the pair's first `model_fetch_started` has the seed's file
count, the `model_fetch_complete` after it counts them downloaded or kept, and
the pair reaches `/readyz` in about the warm time. The seed
does not change `jit_compile` after `worker_ready`, so compare that count with
a cold start of the same image: it should not grow.

To make a seed:

1. Run a pair of the release's engine image and plan to `/readyz`, outside the
   TEE (a bring-up host with the target GPU and driver), and send it the
   warmup. Copy its whole `paths.kernel_cache_dir` (`/tmp/dsv41/kernel-cache`).
2. `scripts/kernel-cache-manifest.py <copy> --repository <owner>/<name>
   --engine-image <engine image@sha256:...> --plan <plan> > manifest.json`.
   It leaves out lock files and partial writes. fetch-model writes every file
   read-only, so a seeded lock file could not be opened for writing.
3. Serve each listed file on the mirror at
   `<repository>/resolve/sha256-<digest>-<plan>/<path>`.
4. In the environment values, set `inference.pair.kernelCache.seed.enabled:
   true` and `inference.pair.kernelCache.seed.manifest` to the manifest text.

The chart does not keep the cache on the node. The pinned C8s (v0.101.9)
refuses every tenant `hostPath` (its `deny-host-namespaces` policy) and has no
StorageClass on its node image (C8s #1129 removed local-path). The node's
writable disk is dm-crypt with a per-boot key and no integrity, so the host
could also corrupt or roll back a cache kept there. A C8s mutable volume
persists but has no integrity either, and a host rollback of it goes
undetected (C8s `docs/volumes.md`). The seed's bytes are pinned instead.

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
- `router.maxConcurrentRequests` (default 0, off) must be at least
  `inference.replicas` x the worker's `--max-running-requests`.
- `inference.contextLength` and `inference.maxRunningRequests` (default 0:
  the model's own value) set the worker flags.

The gateway sends an `X-SMG-Routing-Key` header on every request it can
identify a conversation for (`services/gateway/src/routing_key.rs`). The
removed PD router's `manual` policy read it. The aggregated router's
`cache_aware` policy does not: it picks a worker by prefix match and load.
