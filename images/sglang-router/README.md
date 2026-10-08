# SGLang Router image

This image contains the router at the exact upstream source in `source.lock`.
Its patch adds worker withdrawal, active-stream counts, a discovery fence,
and drain status. It keeps upstream discovery and model routing.

The image uses a pinned Python runtime. `requirements.lock` fixes every
Python dependency version and file hash. It has a separate image name and
digest. Updating it does not update inference workers or download model files.

Build from this directory. Supply `SOURCE_REVISION` and `SOURCE_DATE_EPOCH`
from the public repository commit. Publish and deploy by immutable digest.
The candidate router rehearsal must pass before this image is ready for use.

Set `--enable-igw` explicitly for model-aware routing. Without this flag,
upstream regular mode ignores the request's model when it selects a worker.
In IGW mode, add workers through discovery or `POST /workers`; do not rely
on `--worker-urls` to populate the registry.

Run the built-image test before a candidate update:

```sh
ROUTER_TEST_IMAGE=<image-at-immutable-digest> \
  python3 -m unittest discover -s tests -p test_router_image.py
```

The test runs a local router and two fake HTTP workers. It checks model
selection, withdrawal, an open stream's drain count, registration fencing,
and recovery. It does not replace the candidate live rehearsal.
