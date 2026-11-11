# Inference serving interface

This document defines the integration boundary for an inference engine.
Confidential Inference releases version this interface and its acceptance tests
together. There is no separate contract version or new deployment controller.

The current implementation uses SGLang. Engine implementation and image builds
belong to the engine publisher. Kubernetes assembly and service acceptance belong
to Confidential Inference. See the [SGLang integration and cleanup plan](../docs/sglang-separation.md)
for the migration from the current image builds. These requirements do not
certify an untested replacement image.

## Responsibilities

| Owner | Required output |
| --- | --- |
| Engine publisher, including confidential-sglang | Fixed engine/router image digests, source and build evidence, documented independent startup commands, model requirements, ports, probes, metrics, and engine tests. |
| Confidential Inference | Kubernetes workloads and connections, model recipe configuration, gateway integration, collection, C8s policy integration, release verification, and service acceptance tests. |
| Deployment | Selected releases and model, infrastructure, placement, resources, storage, secret references, monitoring destinations, and execution of installation/promotion procedures. |

An image may contain several executables. Installing that image does not select
which processes share a pod or restart together. The chart defines those choices.
Do not start an entire host Compose stack inside a pod merely to reuse its launcher.

## Interfaces to implement and check

| Surface | Requirements |
| --- | --- |
| Inference | Supply the gateway's supported upstream request/response behavior: model naming, text/chat inference, streams that complete correctly, tool calls where advertised, token usage including cached input, bounded errors, and defined cancellation behavior. Keep client credentials out of forwarded requests. |
| Lifecycle | Document independent commands, startup readiness, ongoing health, admission withdrawal, drain completion, and recovery boundaries. Define which GPU ranks must recover together and dependencies on shared caches or hosts. Readiness does not establish full acceptance. |
| Metrics | Expose worker and router Prometheus endpoints separately. Document address/port/path, metric meaning, units, and permitted labels. Identify installation, component, and replica without exporting credentials, request content, or uncontrolled client values. GPU hardware metrics remain a separate source. |
| Confidential execution | Supply the information required to verify images, model identity/bytes, actual commands, environment, mounts, connections, secret access, and C8s policy bindings. The framework independently checks evidence; a backend health response is insufficient. |

The [gateway OpenAPI](gateway-inference.openapi.json) specifies the public API.
It does not, on its own, define all upstream lifecycle or verification behavior.
The [usage interface](product-usage.md) and [metrics reference](../docs/observability-metrics.yaml)
remain authoritative for their existing fields. Extend those definitions rather
than maintaining copies here. Engine-specific capability negotiation, exact
lifecycle operations, metric requirements, and compatibility checks still need
implementation review.

## How Kubernetes consumes the images

The [application chart](../helm/confidential-inference/README.md) selects the
engine/router commands and connects the resulting endpoints to the gateway and
collector. Model-specific engine flags stay in chart configuration and templates,
not in common gateway code. The schema validates supported configuration.

The collector scrapes engine, router, gateway, and GPU endpoints as separate
targets. The deployment supplies an approved destination and credentials; the
framework applies the required label and export restrictions. Metrics storage,
retention, dashboards, and alerts belong to the deployment. Grafana queries a
metrics backend; it is not the worker's scrape receiver.

## Acceptance along the deployment lifecycle

1. **Merge:** review image integration, rendered workloads, configuration, and
   tests together. An engine fix can require an explicit interface change.
2. **Release:** verify published artifacts and bind exact digests and evidence
   in the signed release. A mutable image tag or a local build is insufficient.
3. **Deploy staging:** the target design uses one GPU and a small model.
4. **Validate staging:** prove inference, sampling, stream completion, credential
   handling, usage, separate metrics targets, and confidentiality for that install.
5. **Deploy candidate:** select the production model and topology with the
   approved image digests and the required model/configuration bindings.
6. **Validate candidate:** repeat installation-specific checks; prove load,
   transfer connectivity, drain, and worker recovery on the actual topology.
7. **Promote:** reuse the validated candidate; preserve rollback and connection
   draining. Promotion and infrastructure selection remain deployment operations.

These are target acceptance requirements. The existing staging release profile
still uses the CPU simulator. A successful chart render, image build, or health
check does not mean that the target lifecycle has been implemented or passed.
