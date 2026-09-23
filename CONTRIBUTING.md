# Contributing

Read the [developer workflow](docs/runbooks/developer-workflow.md) before you
make a change or create a release.

Open an issue before you make a large change. Keep each pull request small and
focused.

Before you submit a change, run:

```sh
V0_ALLOW_MISSING_PINNED_ROUTER_IMAGE=1 bash scripts/ci-validate.sh
```

Do not add live addresses, credentials, private infrastructure, benchmark
results, or generated build files. Pin container images and workflow actions
by digest or full commit. Add tests for changed behavior.

By submitting a change, you agree that it is available under the repository
license.
