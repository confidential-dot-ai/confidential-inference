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
