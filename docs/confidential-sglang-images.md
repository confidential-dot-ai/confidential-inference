# confidential-sglang images

`confidential-dot-ai/confidential-sglang` builds the SGLang engine image and
the router image. This repository defines how they run (the chart, the
recipes, the contracts) and signs framework releases that pin them. It pins
them as it pins C8s: by a release record of the repository that builds them,
not by its own image publication.

## The release record

confidential-sglang's image workflow (`.github/workflows/images.yml`) builds
each image twice on clean runners, requires equal digests, and pushes the
image. It then creates the GitHub release `images-<12hex>`, where `<12hex>`
is the first 12 hex digits of the source commit, with one asset,
`images-<12hex>.json`. confidential-sglang defines the format in
`confidential/ci/release_record.py`:

```json
{
  "schema": "confidential.ai/confidential-sglang-images/v1",
  "repository": "https://github.com/confidential-dot-ai/confidential-sglang",
  "sourceCommit": "<40 hex>",
  "sourceDateEpoch": 1795169221,
  "run": {
    "id": 44716530121,
    "attempt": 1,
    "repository": "confidential-dot-ai/confidential-sglang-ci",
    "workflow": "confidential-dot-ai/confidential-sglang-ci/.github/workflows/images.yml@refs/heads/main",
    "url": "https://github.com/confidential-dot-ai/confidential-sglang-ci/actions/runs/44716530121/attempts/1"
  },
  "images": [
    {
      "name": "engine",
      "image": "ghcr.io/confidential-dot-ai/confidential-sglang/engine",
      "digest": "sha256:<64 hex>",
      "builds": ["sha256:<64 hex>", "sha256:<64 hex>"],
      "reference": "ghcr.io/confidential-dot-ai/confidential-sglang/engine@sha256:<64 hex>",
      "tag": "sha-<40 hex>"
    },
    {"name": "router", "...": "the same fields"}
  ]
}
```

`scripts/confidential_sglang_release.py` checks:

- The record holds exactly these fields; `sourceDateEpoch` is optional and,
  when present, is a positive integer. Records are at most 64 KiB.
- `sourceCommit` is the commit the release name names.
- `images` holds `engine` and `router`, once each and sorted by name. Each
  `image` is that component's exact untagged name below
  `ghcr.io/confidential-dot-ai/confidential-sglang/`; its `reference` and
  `tag` must match its digest and source commit.
- `builds` are the digests of the two clean builds. Both must equal
  `digest`. They replace this repository's own two-build image audit.
- `run` is a run of the images workflow **on `main`**, in
  confidential-sglang or in `confidential-sglang-ci`. That repository only
  calls `confidential-sglang/.github/workflows/images.yml@main` with a
  commit, while Actions are off in confidential-sglang.
- The run ID and attempt are positive integers. Its URL names that
  repository, ID and attempt; its workflow names that repository's
  `.github/workflows/images.yml@refs/heads/main`.

The manifest stores the record normalized: each image by digest with its
`buildDigests`, and the run ID as `runId`. Its record hash binds the original
bytes, including the run repository, attempt and workflow.

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
