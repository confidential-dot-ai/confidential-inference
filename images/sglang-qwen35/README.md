# SGLang Qwen3.5-0.8B staging image

The staging worker: [Qwen/Qwen3.5-0.8B](https://huggingface.co/Qwen/Qwen3.5-0.8B)
at revision `2fc06364715b967f1860aea9cf38778875588b17`, one worker on one GPU,
behind the SGLang router. The model loads in minutes, so a change to the
engine, the chart or C8s goes through the whole staging path before it
reaches the production model.

The engine is the production worker's engine (`images/sglang`): the same
pinned CUDA base, Ubuntu snapshot, Python wheels, official upstream SGLang
commit and build-time hardening. The Dockerfile copies those stages
unchanged, and `tests/images/sglang/test_qwen35_recipe.py` checks that they
stay identical. Upstream SGLang at the pinned commit has the Qwen3.5 model
(`sglang/srt/models/qwen3_5.py`), the `qwen3_coder` tool parser and the
`qwen3` reasoning parser; the build imports them.

| File | What it is |
| --- | --- |
| `Dockerfile` | The production engine stages, plus the model pin and the helper. No CPU simulator |
| `Dockerfile.dockerignore` | The build context: these files and the `images/sglang` engine inputs |
| `model-manifest.json` | The byte manifest of the pinned revision (`fetch-model manifest`), SHA-256 `625963f6…` |
| `serve.sh` | `qwen35-serve` in the image: fetch, verify and serve with `docker run` |
| `build.sh` | A local build (not a release image) |

The weights are not in the image. In the cluster the worker downloads them
at each start (`inference.model.download`) or reads a C8s model volume, and
`wait-for-model` checks every byte against the manifest first. The chart
renders the worker argv itself; the staging values layer is
`tests/fixtures/deployments/qwen35-staging-values.yaml`, and
`tests/helm/test_qwen35_staging.py` checks that the chart argv equals
`qwen35-serve args`.

The Release images workflow builds and publishes this image as
`ghcr.io/confidential-dot-ai/confidential-inference/sglang-qwen35`, with the
same two-build reproducibility audit as `sglang`. `release/spec.yaml` names it
as `images.sglangStagingWorker`; the release build adds the published digest.
An environment selects it with `inference.workerImage: sglangStagingWorker`.

## Run with Docker

```sh
img=ghcr.io/confidential-dot-ai/confidential-inference/sglang-qwen35@sha256:<digest>
mkdir -p /data/models/qwen35-0.8b
docker run --rm --user 0 -v /data/models/qwen35-0.8b:/models/qwen35-0.8b "$img" qwen35-serve fetch
docker run -d --gpus device=0 --shm-size 8g -p 30000:30000 \
  -v /data/models/qwen35-0.8b:/models/qwen35-0.8b:ro "$img" qwen35-serve serve
```

## Change the model revision

Change the revision and the hashes in `serve.sh`, the Dockerfile labels and
the staging values layer, and regenerate the manifest:

```sh
python3 images/sglang/fetch_model.py manifest \
  --repository Qwen/Qwen3.5-0.8B --revision <sha> > images/sglang-qwen35/model-manifest.json
```
