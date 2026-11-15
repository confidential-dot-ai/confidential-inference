# SGLang Qwen3.5-0.8B staging image

The staging worker: [Qwen/Qwen3.5-0.8B](https://huggingface.co/Qwen/Qwen3.5-0.8B)
at revision `2fc06364715b967f1860aea9cf38778875588b17`, one worker on one GPU,
behind the SGLang router. The model loads in minutes, so a change to the
engine, the chart or C8s goes through the whole staging path before it
reaches the production model.

**Staging only, and temporary.** The model weights are inside the image
until a model mirror or persistent model disks exist.

## One image: the production image plus one weights layer

`Dockerfile` holds `images/sglang-dsv41-flash/Dockerfile` verbatim, between
two marker lines, and then one stage `FROM engine` (the production stage).
The engine layers are the production layers: the same instructions on the
same pinned inputs (CUDA base, Ubuntu snapshot, hashed wheels, upstream SGLang
commit, build-time hardening, simulator), with the same reproducible build
settings. `tests/images/sglang-qwen35-0.8b/test_recipe.py` fails if the copy
differs from the production Dockerfile.

The staging stage adds one layer:

- the Qwen files at `/opt/confidential-inference/models/qwen35-0.8b`. The
  production image's `fetch-model` downloads them from Hugging Face at build
  time and checks each file's size and SHA-256 against `model-manifest.json`,
  whose SHA-256 (`625963f6…`) the Dockerfile pins. The manifest is written
  next to them as `.model-lock-local-manifest.json`;
- `qwen35-serve`, a helper for `docker run` outside Kubernetes.

Owner (root), modes (0555 directories, 0444 files) and times (epoch 0) are
fixed, so two clean builds give the same bytes. The Release images workflow
proves it with its two-build reproducibility audit.

**The weight files are never in Git** (no Git LFS either). The repository
holds only the byte manifest and the revision pin. A test fails if a weight
file, a large tokenizer file or an LFS attribute is tracked.

| File | What it is |
| --- | --- |
| `Dockerfile` | The production Dockerfile verbatim, then the one weights layer |
| `Dockerfile.dockerignore` | The production build context, plus the two files below |
| `model-manifest.json` | The byte manifest of the pinned revision (`fetch-model manifest`) |
| `serve.sh` | `qwen35-serve` in the image: verify the image files and serve with `docker run` |
| `build.sh` | A local build (not a release image) |

## In the cluster

The chart's model mode `inference.model.source: image` runs this image with
no download, no egress, no init container and no model volume. The model
path is the image directory, and `wait-for-model --image-files` checks every
byte against the manifest before SGLang starts. The staging values layer is
`tests/fixtures/deployments/qwen35-staging-values.yaml`, and
`tests/helm/test_qwen35_staging.py` checks that the chart argv equals
`qwen35-serve args`.

The Release images workflow publishes the image as
`ghcr.io/confidential-dot-ai/confidential-inference/sglang-qwen35-0.8b`.
`release/spec.yaml` names it as `images.sglangQwen35`; the release build adds
the published digest. An environment selects it with
`inference.workerImage: sglangQwen35`.

## Run with Docker

```sh
img=ghcr.io/confidential-dot-ai/confidential-inference/sglang-qwen35-0.8b@sha256:<digest>
docker run -d --gpus device=0 --shm-size 8g -p 30000:30000 "$img" qwen35-serve serve
```

## Change the model revision

Regenerate the manifest, then change the revision and the hashes in the
Dockerfile (`--manifest-sha256` and the labels), `serve.sh` and the staging
values layer:

```sh
python3 images/sglang-dsv41-flash/fetch_model.py manifest \
  --repository Qwen/Qwen3.5-0.8B --revision <sha> > images/sglang-qwen35-0.8b/model-manifest.json
```
