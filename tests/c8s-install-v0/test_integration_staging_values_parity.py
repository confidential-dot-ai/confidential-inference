"""Check that the public staging values stay in step with the deployed ones.

`c8s/integration-staging-values.yaml` is the public, reviewable file. The
file the deployment actually reads is `environments/values-staging.yaml`
in the confidential-inference-internal repository. The two files must
agree on every field the allowlist generator reads and on every field
that reaches a rendered container, or the public file stops describing
what is really deployed.

The internal repository is not present in public CI. This test reads its
path from the CONFIDENTIAL_INFERENCE_INTERNAL environment variable. There
is no default path. The test skips cleanly when the variable is unset or
names a directory that is not a Git checkout.
"""

from __future__ import annotations

import copy
import os
import subprocess
import unittest
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
PUBLIC_VALUES_PATH = ROOT / "c8s/integration-staging-values.yaml"
BASE_VALUES_PATH = ROOT / "helm/confidential-inference/values.yaml"
INTERNAL_REPO_ENV = "CONFIDENTIAL_INFERENCE_INTERNAL"
INTERNAL_VALUES_RELATIVE_PATH = "environments/values-staging.yaml"

# Fields that legitimately differ between the public and the internal file,
# with the reason. Add a field here only when the difference is intended;
# every other field in the comparison list below must be equal.
ALLOWED_DIFFERENCES: set[str] = {
    # The public file carries placeholder node names. The real node names are
    # infrastructure values and stay in the internal repository. The chart
    # renders these two fields into a pod nodeSelector only. They are not an
    # input to the c8s allowlist, so a difference here cannot change policy.
    "scheduling.gatewayNodeName",
    "scheduling.inferenceNodeName",
}


def find_internal_repo() -> Path | None:
    """Return the internal repository checkout, or None when it is absent.

    The path comes only from the environment. A maintainer path must not
    become a default in this repository.
    """
    configured = os.environ.get(INTERNAL_REPO_ENV)
    if not configured:
        return None
    candidate = Path(configured)
    return candidate if (candidate / ".git").exists() else None


def deep_merge(base: Any, override: Any) -> Any:
    """Merge override onto base the way Helm merges values files: dicts
    merge key by key, and every other type (including lists) is replaced
    whole by the override."""
    if isinstance(base, dict) and isinstance(override, dict):
        merged = copy.deepcopy(base)
        for key, value in override.items():
            merged[key] = deep_merge(merged.get(key), value)
        return merged
    return copy.deepcopy(override)


def get_path(document: dict, dotted_path: str) -> Any:
    value: Any = document
    for part in dotted_path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise KeyError(f"{dotted_path!r} is missing at {part!r}")
        value = value[part]
    return value


# Every field the allowlist generator reads from the staging values file,
# plus every field that reaches a rendered container, per
# helm/confidential-inference/templates/gateway.yaml and the sibling
# router/metricsCollector/kubeStateMetrics templates.
COMPARED_FIELDS = [
    "environment",
    "images.gateway",
    "images.sglang",
    "images.sglangWorker",
    "images.sglangRouter",
    "images.metricsCollector",
    "images.dcgmExporter",
    "images.nodeExporter",
    "images.kubeStateMetrics",
    "images.c8sOperator",
    "images.stateMounter",
    "scheduling.gatewayNodeName",
    "scheduling.inferenceNodeName",
    "namedWorkloadProxy.enabled",
    "attestationReceipts.policyMode",
    "attestationReceipts.releaseId",
    "attestationReceipts.releaseBundleSha256",
    "attestationReceipts.expectedStaticAllowlistSha256",
    "attestationReceipts.evidenceBaseUrl",
    "attestationReceipts.gatewayPort",
    "attestationReceipts.routerPort",
    "attestationReceipts.firstWorkerPort",
    "attestationReceipts.metricsCollectorPort",
    "attestationReceipts.kubeStateMetricsPort",
    "attestationReceipts.platform",
    "attestationReceipts.targets",
    "inference.mode",
    "inference.replicas",
    "inference.attestedWorkloads",
    "router.attestedWorkload",
    "metricsCollector.attestedWorkload",
    "kubeStateMetrics.attestedWorkload",
    "gateway.attestedWorkload",
]


class IntegrationStagingValuesParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.internal_repo = find_internal_repo()
        if cls.internal_repo is None:
            raise unittest.SkipTest(
                "no confidential-inference-internal checkout found; set "
                f"{INTERNAL_REPO_ENV} to the path of a checkout of the "
                "confidential-inference-internal repository"
            )
        try:
            result = subprocess.run(
                ["git", "-C", str(cls.internal_repo), "show",
                 f"origin/main:{INTERNAL_VALUES_RELATIVE_PATH}"],
                capture_output=True, text=True, check=True,
            )
        except (subprocess.CalledProcessError, OSError) as error:
            raise unittest.SkipTest(
                f"could not read {INTERNAL_VALUES_RELATIVE_PATH} from "
                f"{cls.internal_repo}: {error}"
            )

        base = yaml.safe_load(BASE_VALUES_PATH.read_text(encoding="utf-8"))
        public_override = yaml.safe_load(PUBLIC_VALUES_PATH.read_text(encoding="utf-8"))
        internal_override = yaml.safe_load(result.stdout)

        cls.public = deep_merge(base, public_override)
        cls.internal = deep_merge(base, internal_override)

    def test_compared_fields_match_between_public_and_internal_values(self) -> None:
        for field in COMPARED_FIELDS:
            if field in ALLOWED_DIFFERENCES:
                continue
            with self.subTest(field=field):
                self.assertEqual(
                    get_path(self.public, field),
                    get_path(self.internal, field),
                    f"c8s/integration-staging-values.yaml and the internal "
                    f"{INTERNAL_VALUES_RELATIVE_PATH} disagree on {field!r}; "
                    "either fix the drift or add the field to "
                    "ALLOWED_DIFFERENCES with a reason",
                )

    def test_allowed_differences_are_still_real_fields(self) -> None:
        # A stale allowance entry hides a field this test no longer checks.
        for field in ALLOWED_DIFFERENCES:
            self.assertIn(field, COMPARED_FIELDS)


if __name__ == "__main__":
    unittest.main()
