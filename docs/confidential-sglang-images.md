# confidential-sglang images

The publisher selected in `release/spec.yaml` builds the SGLang engine image
and router image. It defaults to `confidential-dot-ai/confidential-sglang`.
This repository defines how they run (the chart, the
recipes, the contracts) and signs framework releases that pin them. It pins
them as it pins C8s: by a release record of the repository that builds them,
not by its own image publication.

## The release record

The publisher's image workflow must build each image twice on clean
runners, require equal digests, and push those exact bytes. It then creates the
GitHub release `images-<12hex>`, where `<12hex>` is the first 12 hex digits
of the source commit, with one asset, `images.json`:

```json
{
  "schema": "confidential.ai/confidential-sglang-images/v1",
  "repository": "confidential-dot-ai/confidential-sglang",
  "sourceCommit": "<40 hex>",
  "runId": 19000000001,
  "images": {
    "engine": {
      "image": "ghcr.io/confidential-dot-ai/confidential-sglang/<name>",
      "digest": "sha256:<64 hex>",
      "buildDigests": ["sha256:<64 hex>", "sha256:<64 hex>"]
    },
    "router": {
      "image": "ghcr.io/confidential-dot-ai/confidential-sglang/<name>",
      "digest": "sha256:<64 hex>",
      "buildDigests": ["sha256:<64 hex>", "sha256:<64 hex>"]
    }
  }
}
```

- The record holds exactly these fields.
- `repository` must equal the publisher selected by the reviewed specification.
- `image` is an untagged name below `ghcr.io/<lowercase repository>/`.
- `buildDigests` are the digests of the two clean builds. Both must equal
  `digest`. They replace this repository's own two-build image audit.
- `runId` is the workflow run that built and pushed the images.

## The pin

`release/spec.yaml` names the record on one line:

```yaml
confidentialSglang:
  repository: confidential-dot-ai/confidential-sglang  # optional; this is the default
  record: images-0123456789ab
```

`release/inputs/confidential-sglang/<record>.json` holds the record bytes.
To pin a published record:

```sh
python3 scripts/confidential_sglang_release.py pin images-0123456789ab
```

The script downloads `images.json` with `gh` from the selected repository,
checks its repository and image namespace, writes the input file, and changes
the record line only. Review the specification and record together. A record
cannot choose a different publisher. For a private publisher, the caller needs
read access; neither credentials nor source files belong in the record.

The record, repository name, source commit and image references become framework
release metadata. Only select a publisher whose metadata may be distributed with
the framework. Private images also need pull access in contract CI and at runtime.
The two-build record does not replace the engine image contract tests or GPU
validation; a new publisher must satisfy those requirements before deployment.

`images-000000000000` is the placeholder until confidential-sglang publishes
its first record. The release build refuses it, so no framework release is
built until the record is pinned.

## In a framework release

The release build reads the record file and adds its images to the release
images by chart image key: `engine` as `images.confidentialSglangEngine` and
`router` as `images.confidentialSglangRouter`. The signed manifest binds
`confidentialSglang`: the record name, the asset name, the SHA-256 of the
record bytes, the source commit, the run ID, and each image with its two
build digests.

`scripts/render-allowlist.py` reads the image configuration (`ENV`,
`ENTRYPOINT`, `CMD`) of a confidential-sglang image from the registry by
digest, as it does for an image of this repository.

A recipe chooses the images (`engine.image`, `routing.image`;
`recipes/README.md`). `images.sglangConfidential` and `images.sglangRouter`
still work and stay the default until they are removed.
