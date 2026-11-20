# confidential-sglang images

`confidential-dot-ai/confidential-sglang` builds the SGLang engine image and
the router image. This repository defines how they run (the chart, the
recipes, the contracts) and signs framework releases that pin them. It pins
them as it pins C8s: by a release record of the repository that builds them,
not by its own image publication.

## The release record

confidential-sglang's image workflow builds each image twice on clean
runners, requires equal digests, and pushes the image. It then creates the
GitHub release `images-<12hex>`, where `<12hex>` is the first 12 hex digits
of the source commit, with one asset, `images-<12hex>.json`:

```json
{
  "schema": "confidential.ai/confidential-sglang-images/v1",
  "repository": "https://github.com/confidential-dot-ai/confidential-sglang",
  "sourceCommit": "<40 hex>",
  "sourceDateEpoch": 1795169221,
  "run": {
    "repository": "example/builds",
    "id": 19000000001,
    "attempt": 1,
    "url": "https://github.com/example/builds/actions/runs/19000000001/attempts/1",
    "workflow": "example/builds/.github/workflows/images.yml@refs/heads/main"
  },
  "images": [
    {
      "name": "engine",
      "image": "ghcr.io/confidential-dot-ai/confidential-sglang/engine",
      "digest": "sha256:<64 hex>",
      "reference": "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:<64 hex>",
      "tag": "sha-<40 hex>",
      "builds": ["sha256:<64 hex>", "sha256:<64 hex>"]
    },
    {
      "name": "router",
      "image": "ghcr.io/confidential-dot-ai/confidential-sglang/router",
      "digest": "sha256:<64 hex>",
      "reference": "ghcr.io/confidential-dot-ai/confidential-sglang/router@sha256:<64 hex>",
      "tag": "sha-<40 hex>",
      "builds": ["sha256:<64 hex>", "sha256:<64 hex>"]
    }
  ]
}
```

- The record holds exactly these fields.
- `images` contains exactly `engine`, then `router`; each image uses that exact
  name below `ghcr.io/confidential-dot-ai/confidential-sglang/`.
- `builds` are the digests of the two clean builds. Both must equal
  `digest`. They replace this repository's own two-build image audit.
- `reference` must match the image and digest; `tag` must name `sourceCommit`.
- `run` identifies the publishing workflow, repository, positive run ID and
  attempt. Its repository can differ from the fixed source repository when
  another repository calls the reusable workflow. The URL and workflow must
  agree with that run repository; the record cannot change the source publisher.

## The pin

`release/spec.yaml` names the record on one line:

```yaml
confidentialSglang:
  record: images-0123456789ab
```

`release/inputs/confidential-sglang/<record>.json` holds the record bytes.
To pin a published record:

```sh
python3 scripts/confidential_sglang_release.py pin images-0123456789ab
```

The script downloads `images-<12hex>.json` with `gh`, checks it, writes the input
file, and changes the record line only. Review both and commit them.

`images-000000000000` is the placeholder for an unselected record. The release
build refuses it until a published record is reviewed and pinned.

## In a framework release

The release build reads the record file and adds its images to the release
images by chart image key: `engine` as `images.confidentialSglangEngine` and
`router` as `images.confidentialSglangRouter`. The signed manifest binds
`confidentialSglang`: the record name, the asset name, the SHA-256 of the
original record bytes, the source commit, `run.id` as `runId`, and each image
with its two build digests as `buildDigests`. Hashing the unchanged bytes also
binds the run repository, attempt, workflow and source timestamp. The image
contract selector uses the same validator.

Previously checked-in records with `runId`, an image map and `buildDigests`
remain readable; their manifest asset name remains `images.json`. New downloads
use the named asset and the published list format above.

`scripts/render-allowlist.py` reads the image configuration (`ENV`,
`ENTRYPOINT`, `CMD`) of a confidential-sglang image from the registry by
digest, as it does for an image of this repository.

A recipe chooses the images (`engine.image`, `routing.image`;
`recipes/README.md`). `images.sglangConfidential` and `images.sglangRouter`
still work and stay the default until they are removed.
