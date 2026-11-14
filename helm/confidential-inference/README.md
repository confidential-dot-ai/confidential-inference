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
  reboot downloads all files again. The startup probe must include the
  download time.
- `sizeLimit` (512Gi by default) must hold the model. The kubelet evicts the
  pod above it. The scratch disk must hold the model and the other node state.
- The scratch disk encryption has no integrity protection. The checks before
  the start find a changed byte. After the start, the host can change blocks
  to random data without detection. With the C8s model volume, dm-verity
  checks every read.

## Worker image

The framework release names every image the chart can run. An environment
chooses the worker image among them with `inference.workerImage`:

- `sglangWorker` (the default): the production SGLang image
  (`images/sglang`, plain upstream SGLang, DeepSeek-V4.1).
- `sglangStagingWorker`: the 1-GPU Qwen3.5-0.8B staging image
  (`images/sglang-qwen35`). It runs the production engine, built from the
  same pinned inputs. Its environment layer is
  `tests/fixtures/deployments/qwen35-staging-values.yaml`: one worker on one
  GPU, the model download pinned by its byte manifest, and the Qwen parsers.

The render fails if the chosen `images` entry is not set.

## Prefill/decode layout (removed)

The chart runs aggregated workers only (`inference-worker-N`, one complete
SGLang server each, behind the router). The prefill/decode layout
(`inference-pd`) and its pairs (`sglang-pair`) were removed: neither the
production recipe nor the staging recipe uses them. `inference.pd.enabled`
stays in the schema so that existing environment values still render; only
`false` is accepted.

## Gateway admission

The gateway admits at most `gateway.protection.inferenceConcurrency`
inference requests, holds up to `gateway.protection.inferenceQueue` more for
`queueTimeoutSeconds`, and answers the rest with 503 at once. The chart
default is 48 with no queue.
`perKeyConcurrency` (128 by default) still bounds one API key.

The gateway sends an `X-SMG-Routing-Key` header on every request it can
identify a conversation for (`services/gateway/src/routing_key.rs`). The
removed PD router's `manual` policy read it. The aggregated router's
`cache_aware` policy does not: it picks a worker by prefix match and load.
