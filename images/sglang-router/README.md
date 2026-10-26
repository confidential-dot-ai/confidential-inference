# SGLang Router image

This image contains the router at the exact upstream source in `source.lock`.
Its patch adds worker withdrawal, active-stream counts, a discovery fence,
and drain status. It keeps upstream discovery and model routing.
It also supports model aliases that map a public name onto backend groups.

The image uses a pinned Python runtime. `requirements.lock` fixes every
Python dependency version and file hash. It has a separate image name and
digest. Updating it does not update inference workers or download model files.

For a local development build, supply `SOURCE_REVISION` and `SOURCE_DATE_EPOCH`
from the public repository commit. Use an immutable digest for image tests.
The candidate router rehearsal must pass before this image is ready for use.

The upstream build-time field uses `SOURCE_DATE_EPOCH`, the fixed timestamp
of the public source commit. A missing or invalid timestamp stops the build.
The build sorts wheel archive entries without changing file contents, RECORD,
permissions, or source timestamps. Installation skips Python bytecode
compilation; Python can compile it at runtime. The release still requires two
clean builds with equal complete image digests. Archive sorting does not
permit different binaries or dependency contents.

Set `--enable-igw` explicitly for model-aware routing. Without this flag,
upstream regular mode ignores the request's model when it selects a worker.
In IGW mode, add workers through discovery or `POST /workers`; do not rely
on `--worker-urls` to populate the registry.

Run the built-image test before a candidate update:

```sh
ROUTER_TEST_IMAGE=<image-at-immutable-digest> \
  python3 -m unittest discover -s tests -p test_router_image.py
```

If the Docker daemon uses a different temporary directory, set
`ROUTER_TEST_TMPDIR` to a directory shared by the test process and daemon.

The test runs a local router and two fake HTTP workers. It checks model
selection, withdrawal, an open stream's drain count, registration fencing,
and recovery. It does not replace the candidate live rehearsal.

## Model routes

Set `CI_ROUTER_MODEL_ROUTES` to the routes JSON. It is environment, so the
exact c8s allowlist pins it; a route change changes the pod and rolls the
router. The router reads it once at start and rejects an invalid document.
Without it, aliases are absent.

```json
{
  "schemaVersion": 1,
  "routes": {"public-model": ["backend-old", "backend-new"]}
}
```

A public model name can select workers from several backend model groups.
The router sends the selected worker's backend model name in the upstream
request. After its first admission, retries stay in that selected backend
group. `GET /model-routes` on the private worker control API returns the
routes.

The routes contain model names only: no worker address, token, model
download credential, or encryption key.

The built-image test checks mixed groups, request model rewriting, and an
open stream across a worker drain. These local checks do not replace the
candidate worker/model rehearsal.

## Development publication

The local publication command below is only for isolated development tests.
Do not deploy its output to production or to a candidate prepared for production.
For those deployments, use the approved `Release images` workflow and signed
release pipeline. See [release publication](../../release/README.md).

For a reviewed development build that has passed the image test, publish
with a Docker registry login in tmpfs:

```sh
python3 images/sglang-router/publish.py --image <local-image> \
  --receipt /protected/path/router-publication.json
```

The script checks the image platform, source label, and build inputs. It records
publication time and the repository digest. This is a development artifact.
It does not provide the approved pipeline's build and publication evidence.

A production-ready candidate uses approved release artifacts and still needs
the router rehearsal and deployment checks.
