# SGLang separation of responsibilities and cleanup

## Target and scope

Confidential Inference should consume published engine/router images instead
of rebuilding SGLang. confidential-sglang remains the engine fork. This repository
owns the Kubernetes integration and the [inference serving interface](../api/inference-serving.md).
An inference engineer can own changes across both repositories.

This PR defines that boundary and the migration work. It does not switch image
digests, remove active build inputs, change workload policy, or replace the
current worker/router arrangement. Those changes require verified replacement
artifacts and behavior checks. Do not describe the old build path as unused.

## Where the integration belongs

| Existing location | Responsibility after separation |
| --- | --- |
| `api/` | Inference serving, usage, and release interface definitions. No new top-level contracts folder. |
| `services/gateway/` | Client authentication, limits, forwarding, streaming, and usage integration. No model-specific worker orchestration. |
| `helm/confidential-inference/` | Worker/router resources, probes, discovery, mounts, GPU requirements, collector, network rules, and recipe settings. No parallel integration chart. |
| `release/` | Bind selected images, workload definitions, model/configuration inputs, policy, and publication evidence into the release. |
| `scripts/` and `.github/workflows/` | Run shared validation and publication logic. Consume engine publication evidence instead of rebuilding engine source after migration. |
| `tests/` | API behavior, render validation, engine integration, confidentiality, and failure handling. Preserve tests of required behavior when builds move. |

## Workload configuration supplied by a deployment

The deployment repository supplies its installation values. It does not copy the
worker/router implementation or bypass the framework chart with an unrelated
C8s launch. Use the chart's existing configuration surface:

| Existing chart input | Deployment selects | Framework supplies or checks |
| --- | --- | --- |
| `images.sglangWorker`, `images.sglangRouter` | Approved published engine/router digests | Release evidence, image configuration, startup compatibility, and policy binding. `images.sglang` is an existing fallback; do not invent a third component for it. |
| `inference.model` | Model identity/revision, volume references, and required byte-verification inputs | Model loading and verification integration. |
| `inference`, including `inference.pd` | Supported recipe, worker counts/roles, resources, GPU settings, and allowed engine arguments | Worker resources, connections, probes, and topology validation. |
| `scheduling`, `router` | Placement and supported router settings | Router workloads, Services, and worker routing configuration. |
| `telemetry` | Approved destination, credential references, and installation identity | Separate scrape targets and required privacy restrictions. |

These are existing input groups, not evidence that every externally built image
already fits them. The engine publisher must document commands, ports, mounts,
probes, metrics, dependencies, and supported topology so the integration can be
implemented against a fixed expectation. C8s executes admitted containers; it
does not replace framework release verification or application integration tests.

Container publication and GitHub Releases are separate mechanisms. A registry
artifact can exist without a GitHub Release. Start artifact selection from
publication and deployment records, trace each digest to its actual source and
build evidence, and distinguish registry availability, observed deployment, and
framework acceptance. None establishes the others by itself. The interface can
be agreed before a compatible replacement artifact is selected.

## Current orchestration: preserve the dependencies before changing it

The chart already orchestrates containers. Moving image builds must not create
a second implementation of that orchestration.

| Existing chart file | What it currently supplies |
| --- | --- |
| `templates/inference-workers.yaml` | Aggregated workers: one single-replica StatefulSet per worker, model-volume integration, GPU annotations, commands, and probes. Updates use `OnDelete`. |
| `templates/inference-pd.yaml` | Prefill/decode configuration and workload assembly. The existing layout can place multiple workers and an Engram holder in one pod. |
| `templates/inference-pairs.yaml` | Paired-layout helpers, identities, and routing/configuration derived from pair definitions. |
| `templates/sglang-router.yaml` | Router Deployment, request/metrics Services, regular or PD startup arguments, and worker addresses. |
| `templates/telemetry-collector.yaml` | Separate scrape targets for gateway, router, workers, and applicable GPU/platform metrics; label restrictions and export configuration. |
| `values.yaml` and `values.schema.json` | Supported topology, image selection, commands, ports, resources, and validation of settings. |

The recipe launcher in the fork is not automatically a compatible pod entrypoint.
The integration needs independently invokable worker/router commands. Shared
Engram pages, localhost addresses, GPU communication, startup order, privileges,
and recovery units must be reconciled with C8s and the actual chart configuration.
Several GPU ranks inside one worker may need to fail together. Separate worker
pods are not automatically safe when they depend on a shared cache or host.

## Cleanup inventory

Classify each file by function, not by the directory name. The actions below
are pending migration work, not deletions made by this PR.

| Current files | Disposition and condition |
| --- | --- |
| `images/sglang/Dockerfile`, `build.sh`, `fetch_source.py`, source/dependency locks | Replace the local engine build with published artifacts and accepted build evidence. Remove these build inputs only after release tooling no longer consumes them. |
| `images/sglang-router/Dockerfile`, `Cargo.lock`, `source.lock`, Python requirements, `canonicalize_wheel.py`, `publish.py` | Move engine/router build ownership to the engine publisher. Retire this build path after reproducibility/publication evidence and integration behavior are covered. |
| `images/sglang-router/patches/` | Compare all six patches with the selected fork: withdrawal/model routes, admission caps, PD relay, no-tokenizer HTTP behavior, pair routing, and private errors. Do not infer equivalence from a patch name or the presence of a bundled router. |
| `images/sglang/wait_for_model.py`, `fetch_model.py` | Preserve model identity, byte verification, encrypted-volume, and loading requirements. Determine whether the verified implementation belongs in a product wrapper or a reusable engine helper. |
| `images/sglang/harden_http.py`; router `private_router.py`, `private_log_sink.py` | Preserve required HTTP restrictions and privacy behavior. Consolidate only after the replacement implements and tests those protections. A wrapper image is justified only by explicit product requirements. |
| `images/sglang/pair_supervisor.py`, `pair_diagnostics.py` | Separate engine process mechanics from product recovery and privacy policy. Replace whole-group restart assumptions only after failure tests establish the supported recovery boundary. |
| `images/sglang/dcgm-counters.csv` and GPU exporter packaging | Keep GPU observability available; decide its packaging separately from engine/router metrics. |
| `images/sglang/simulator-upstream/`, simulator patches, `rehearsal/`, `Dockerfile.gpu-test*` | Trace consumers. One-GPU staging changes the requirement but does not establish that all simulator or isolated test tooling is obsolete. |
| `tests/images/sglang*`, `tests/image-workflow/`, `tests/helm/`, `tests/telemetry/` | Remove build-layout assertions only with their retired inputs. Keep behavior, security, streaming, metrics, and recovery checks; use small fixtures where sufficient. |

## Release and migration gates

- [ ] Select immutable engine/router artifacts and verify their source, build,
  publication evidence, commands, dependencies, and supported GPU/model settings.
  Do not treat a successful local Docker build as release evidence.
- [ ] Inventory every command and helper the chart expects from the current
  images. Require a compatible replacement or an explicit reviewed chart change.
- [ ] Compare the six router patches and product wrappers with the replacement.
  Record retained requirements and the tests that establish equivalence.
- [ ] Update affected-image selection, publication manifests, release schemas,
  manifest generation, image-config inspection, and policy generation as needed
  to verify externally published images. Preserve signature and digest checks.
- [ ] Render the exact workloads and derive their C8s policy. Review changed
  entrypoints, environment, mounts, GPU access, connections, and secret grants.
- [ ] Deploy and validate one-GPU/small-model staging with the selected images,
  including separate worker/router metrics reaching the configured receiver.
- [ ] Validate the production-model candidate: actual inference, streams, model
  verification, privacy, load, draining, and the supported failure/recovery paths.
- [ ] Remove the superseded image build inputs, workflow branches, fixtures, and
  documentation only after their consumers have moved. Keep rollback artifacts.

Independent worker/router images are the intended publication boundary. If the
selected publisher currently provides a combined image, record that explicitly
and verify its role-specific commands; do not invent an image split or digest.
No new contract version, custom deployment resource, or framework dependency is
introduced by this plan. Start with the existing chart and release structure.
