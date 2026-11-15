"""Unit tests for the framework release tools in scripts/.

These tests use no network, no cluster, and no c8s binary. They cover the
parts of the tools that decide the framework manifest and a deployment
allowlist.

The repository holds no digest of an image that it builds, so the tests
render the chart with fixtures/release-values.yaml: fixture digests of every
framework image. tests/fixtures/deployments/ holds two example deployments
with example addresses. fixtures/staging-allowlist.json is the allowlist that
the c8s CLI of the c8s pin generates for the staging example;
scripts/bump-c8s.py regenerates it with staging_allowlist().
"""

from __future__ import annotations

import contextlib
import copy
import functools
import importlib.util
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]


def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


GEN = load("generate_release_allowlist", "scripts/generate-release-allowlist.py")
MAN = load("build_release_manifest", "scripts/build-release-manifest.py")
REN = load("render_allowlist", "scripts/render-allowlist.py")
NODE = load("fetch_node_manifest", "scripts/fetch-node-manifest.py")
SPEC = sys.modules["release_spec"]
FIXTURES = ROOT / "tests/release-v1/fixtures"
DEPLOYMENTS = ROOT / "tests/fixtures/deployments"
PRODUCTION = SPEC.Deployment((DEPLOYMENTS / "production-values.yaml",),
                             DEPLOYMENTS / "production-allowlist-policy.json")
STAGING = SPEC.Deployment((DEPLOYMENTS / "production-values.yaml", DEPLOYMENTS / "staging-values.yaml"),
                          DEPLOYMENTS / "staging-allowlist-policy.json",
                          DEPLOYMENTS / "staging-accepted-lint-findings.json")
OVERLAY = FIXTURES / "release-values.yaml"
# The environment name that each example deployment passes to the render (--environment).
ENVIRONMENTS = {PRODUCTION: "production", STAGING: "staging"}
STAGING_ALLOWLIST = FIXTURES / "staging-allowlist.json"
REPOSITORY_CONFIGS = json.loads((FIXTURES / "repository-image-config.json").read_text())
RELEASE_IMAGES = yaml.safe_load(OVERLAY.read_text())["images"]
# The rollout client uses the same pinned Python base as the router fixture.
# Its program is signed in chart argv; this synthetic digest tests packaging.
REPOSITORY_CONFIGS[RELEASE_IMAGES["rolloutClient"]] = {
    "entrypoint": [], "cmd": ["python3"],
    "env": REPOSITORY_CONFIGS[RELEASE_IMAGES["sglangRouter"]]["env"][:],
}

REPOSITORY = "https://github.com/confidential-dot-ai/confidential-inference"
LOCK = ROOT / "release/inputs/c8s-source-lock.json"


@functools.cache
def rendered(deployment) -> list[dict]:
    """The chart rendered with the deployment values and its policy settings. Do not change it."""
    with tempfile.TemporaryDirectory() as temporary:
        overlay = Path(temporary) / "release-values.yaml"
        overlay.write_text(yaml.safe_dump({**yaml.safe_load(OVERLAY.read_text()),
                                           "environment": ENVIRONMENTS[deployment]}))
        return REN.render_chart(MAN.CHART, deployment, REN.read_allowlist_policy(deployment.policy)["chart"],
                                overlay)


def publication(images: dict[str, str], *, commit: str = "b" * 40, base_ref: str = "v0.13.28-rc.2",
                base_commit: str = "c" * 40) -> dict:
    return {
        "schema": "confidential.ai/image-publication-manifest/v2",
        "source": {"repository": REPOSITORY, "commit": commit, "baseRef": base_ref, "baseRefCommit": base_commit},
        "images": [{"name": name, "digest": digest} for name, digest in sorted(images.items())],
    }


def published_release_images() -> dict[str, str]:
    """The fixture digests of the repository images, as the image publication names them."""
    return dict(image.split("@", 1) for image in RELEASE_IMAGES.values()
                if image.startswith(SPEC.REPOSITORY_IMAGES))


def write_release(directory: Path, manifest: dict) -> None:
    """Put a release manifest and an empty Sigstore bundle where the build downloads them."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "release-bundle.json").write_text(json.dumps(manifest))
    (directory / "release-bundle.sigstore.json").write_text("{}")


def build_framework(evidence: dict, base: dict | None = None, tag: str = "v0.17.0") -> dict[str, bytes]:
    """Build a framework release with the signature and Git checks replaced."""
    with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
        evidence_path = Path(temporary) / "publication.json"
        evidence_path.write_text(json.dumps(evidence))
        download_dir = Path(temporary) / "base"
        if base is not None:
            write_release(download_dir, base)
        stack.enter_context(mock.patch.object(MAN, "verify_image_source_boundary"))
        stack.enter_context(mock.patch.object(MAN, "changed_paths", return_value=[]))
        stack.enter_context(mock.patch.object(MAN.release_signature, "verify_release_signature"))
        stack.enter_context(mock.patch.object(MAN.shutil, "which", return_value="/usr/bin/cosign"))
        return MAN.build(tag, MAN.CHART, LOCK, "d" * 40, evidence_path, download_dir)


@functools.cache
def framework_bytes() -> bytes:
    return build_framework(publication(published_release_images()))["release-bundle.json"]


def framework_manifest() -> dict:
    return json.loads(framework_bytes())


def render_deployment(deployment=STAGING, c8s: Path | None = None, manifest: dict | None = None,
                      verify_core_seed=None, environment: str = "staging") -> dict[str, bytes]:
    """Render a deployment allowlist. Without `c8s`, the fixture allowlist replaces the c8s CLI
    and the seed render check is skipped, unless `verify_core_seed` replaces it."""
    generated = STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n")
    generate = REN.ALLOWLIST_GENERATOR["generate"] if c8s else lambda *_args, **_kwargs: generated
    verify = verify_core_seed or (REN.ALLOWLIST_GENERATOR["verify_core_seed"] if c8s else lambda *_args: None)
    with mock.patch.dict(REN.ALLOWLIST_GENERATOR, {"generate": generate, "verify_core_seed": verify,
                                                   "image_config": REPOSITORY_CONFIGS.__getitem__}):
        return REN.render(manifest or framework_manifest(), REN.MAN["read_spec"](), deployment,
                          c8s or Path("c8s"), None, MAN.sha256(framework_bytes()), environment)


def staging_allowlist(c8s: Path) -> bytes:
    """Return the fixture allowlist as the c8s CLI binary `c8s` generates it.

    scripts/bump-c8s.py writes it to fixtures/staging-allowlist.json when the
    release moves to another c8s release.
    """
    return render_deployment(c8s=c8s)["allowlist.json"]


def rendered_workers(deployment) -> list[dict]:
    return [item for item in rendered(deployment) if item.get("kind") == "StatefulSet"
            and (item.get("metadata", {}).get("name", "").startswith("inference-worker-")
                 or item.get("metadata", {}).get("name", "").startswith("inference-pd"))]

DIGEST = "sha256:" + "a" * 64
IMAGE = f"ghcr.io/example/app@{DIGEST}"
CORE = f"ghcr.io/confidential-dot-ai/c8s-operator@sha256:{'b' * 64}"
POLICY = {"chart": {"namespace": "confidential-inference"}, "kubernetes": {"serviceHost": "10.53.0.1"}}


def controller(kind="StatefulSet", name="worker", container=None, volumes=None, annotations=None, **pod):
    spec = {"enableServiceLinks": False, "containers": [container or {"name": "app", "image": IMAGE}]}
    spec.update(pod)
    if volumes is not None:
        spec["volumes"] = volumes
    return {
        "kind": kind,
        "metadata": {"name": name},
        "spec": {"replicas": 1, "template": {"metadata": {"annotations": annotations or {}}, "spec": spec}},
    }


class EnvironmentTests(unittest.TestCase):
    def env(self, obj, configs=None, cdi=None):
        container = obj["spec"]["template"]["spec"]["containers"][0]
        configs = configs or {IMAGE: {"env": ["PATH=/usr/bin", "PATH=/bin", "A=1"], "entrypoint": ["/a"], "cmd": []}}
        return GEN.container_env(obj, container, configs, POLICY, cdi)

    def test_image_env_last_value_wins_and_platform_values_are_added(self):
        values = self.env(controller())
        self.assertEqual(values["PATH"], "/bin")
        self.assertEqual(values["HOSTNAME"], "worker-0")
        self.assertEqual(values["KUBERNETES_SERVICE_HOST"], "10.53.0.1")
        self.assertEqual(values["KUBERNETES_PORT_443_TCP"], "tcp://10.53.0.1:443")

    def test_pod_env_expands_earlier_names_and_field_refs(self):
        container = {"name": "app", "image": IMAGE, "env": [
            {"name": "B", "value": "x"},
            {"name": "C", "value": "$(B)-y-$$(B)"},
            {"name": "POD", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
        ]}
        values = self.env(controller(container=container))
        self.assertEqual(values["C"], "x-y-$(B)")
        self.assertEqual(values["POD"], "worker-0")

    def test_node_specific_values_are_refused(self):
        container = {"name": "app", "image": IMAGE, "env": [
            {"name": "HOST_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.hostIP"}}}]}
        with self.assertRaisesRegex(GEN.GenerationError, "differs per node"):
            self.env(controller(container=container))

    def test_service_links_and_random_pod_names_are_refused(self):
        obj = controller()
        obj["spec"]["template"]["spec"]["enableServiceLinks"] = True
        with self.assertRaisesRegex(GEN.GenerationError, "enableServiceLinks"):
            self.env(obj)
        with self.assertRaisesRegex(GEN.GenerationError, "HOSTNAME"):
            self.env(controller(kind="Deployment"))
        self.assertEqual(self.env(controller(kind="Deployment", hostname="gateway"))["HOSTNAME"], "gateway")

    def test_gpu_container_needs_the_cdi_record(self):
        container = {"name": "app", "image": IMAGE, "resources": {"limits": {"nvidia.com/gpu": 4}}}
        with self.assertRaisesRegex(GEN.GenerationError, "CDI record is absent"):
            self.env(controller(container=container))
        cdi = {"env": {"NVIDIA_VISIBLE_DEVICES": "void"}, "mounts": []}
        self.assertEqual(self.env(controller(container=container), cdi=cdi)["NVIDIA_VISIBLE_DEVICES"], "void")


class MountTests(unittest.TestCase):
    def test_rules_follow_volume_class_and_c8s_injection(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [
            {"name": "tmp", "mountPath": "/tmp"},
            {"name": "config", "mountPath": "/mnt/c8s-data/config", "readOnly": True},
        ]}
        obj = controller(
            container=container,
            volumes=[{"name": "tmp", "emptyDir": {}}, {"name": "config", "configMap": {"name": "c"}}],
            annotations={
                "confidential.ai/cw": "worker",
                "confidential.ai/c8s-secrets": "P=/p",
                "confidential.ai/c8s-volumes": "dsv4=/v/dsv4",
                "confidential.ai/c8s-volume-dir": "/mnt/c8s-data/models",
            },
        )
        rules = GEN.container_mounts(obj, container, None)
        self.assertEqual(rules, [
            {"destination": "/etc/c8s/certs", "kind": "emptyDir"},
            {"destination": "/mnt/c8s-data/config", "kind": "data"},
            {"destination": "/mnt/c8s-data/models/dsv4", "kind": "data"},
            {"destination": "/run/c8s/secrets", "kind": "emptyDir"},
            {"destination": "/tmp", "kind": "emptyDir"},
        ])

    def test_data_outside_the_data_root_is_refused(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [{"name": "config", "mountPath": "/etc/app"}]}
        obj = controller(container=container, volumes=[{"name": "config", "configMap": {"name": "c"}}])
        with self.assertRaisesRegex(GEN.GenerationError, "below /mnt/c8s-data/"):
            GEN.container_mounts(obj, container, None)

    def test_declared_attestation_sidecar_pins_the_nri_socket_mount(self):
        container = {"name": "cds-attest", "image": IMAGE,
                     "command": ["/c8s"], "args": ["cds-attest"]}
        obj = controller(container=container, annotations={"confidential.ai/cw": "gateway"})
        rules = GEN.container_mounts(obj, container, None, c8s_release="v0.44.6")
        self.assertIn({"destination": "/run/c8s/workload-claims", "kind": "host",
                       "source": "/var/run/nri-image-policy", "readOnly": True}, rules)
        self.assertEqual(len(rules), 2)
        self.assertEqual(GEN.container_mounts(obj, container, None, c8s_release="v0.42.0"),
                         [{"destination": "/etc/c8s/certs", "kind": "emptyDir"}])
        # From c8s #915 the node policy observes its own socket mount as a
        # platform mount, and a host rule for it would refuse the secrets grant.
        self.assertEqual(GEN.container_mounts(obj, container, None, c8s_release="v0.50.0"),
                         [{"destination": "/etc/c8s/certs", "kind": "emptyDir"}])
        obj["spec"]["template"]["metadata"]["annotations"] = {}
        self.assertEqual(GEN.container_mounts(obj, container, None, c8s_release="v0.44.6"), [])

    def test_host_path_pins_source_and_mode(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [{"name": "proc", "mountPath": "/host/proc", "readOnly": True}]}
        obj = controller(container=container, volumes=[{"name": "proc", "hostPath": {"path": "/proc"}}])
        self.assertEqual(GEN.container_mounts(obj, container, None),
                         [{"destination": "/host/proc", "kind": "host", "source": "/proc", "readOnly": True}])


class StagingValidationTests(unittest.TestCase):
    def test_fixed_client_has_exact_process_environment_and_certificate_mounts(self):
        pod = next(item for item in rendered(STAGING) if item.get("kind") == "Deployment"
                   and item["metadata"]["name"] == "gateway-update-agent")
        policy = REN.read_allowlist_policy(STAGING.policy)
        self.assertIn("Deployment/gateway-update-agent", {item["controller"] for item in policy["workloads"]})
        client = pod["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(GEN.pod_name(pod), "gateway-update-agent")
        environment = GEN.container_env(pod, client, {client["image"]: {"env": []}}, policy, None)
        self.assertEqual(environment["UPDATE_NAMESPACE"], policy["chart"]["namespace"])
        self.assertEqual(environment["UPDATE_SECRET"], "gateway-update-task")
        self.assertEqual(json.loads(environment["UPDATE_HOSTS"]),
                         ["c8s-gateway.confidential-inference-staging.svc.cluster.local"])
        mounts = GEN.container_mounts(pod, client, None)
        self.assertEqual(mounts, [{"destination": "/etc/c8s/certs", "kind": "emptyDir"}])
        entry = {"initContainers": [], "containers": [{"digest": client["image"].split("@")[1],
                 "command": {"policy": "exact", "argv": client["command"]},
                 "args": {"policy": "exact", "argv": client["args"]}}]}
        selected = {"workloads": [{"name": "gateway-update-agent", "controller": "Deployment/gateway-update-agent"}]}
        allowlist = {"workloads": {"gateway-update-agent": entry}}
        REN.require_allowlist_contract(allowlist, selected, [], [pod], {})
        changed = copy.deepcopy(allowlist)
        changed["workloads"]["gateway-update-agent"]["containers"][0]["args"]["argv"][-1] = "unreviewed code"
        with self.assertRaisesRegex(REN.ManifestError, "process differs"):
            REN.require_allowlist_contract(changed, selected, [], [pod], {})


class ProcessTests(unittest.TestCase):
    config = {"entrypoint": ["/entry"], "cmd": ["--default"]}

    def test_runtime_merge_of_command_and_args(self):
        base = {"name": "app", "image": IMAGE}
        self.assertEqual(GEN.effective_process(base, self.config)["command"], ["/entry"])
        self.assertEqual(GEN.effective_process(base, self.config)["args"], ["--default"])
        with_args = GEN.effective_process({**base, "args": ["--x"]}, self.config)
        self.assertEqual((with_args["command"], with_args["args"]), (["/entry"], ["--x"]))
        with_command = GEN.effective_process({**base, "command": ["/other"]}, self.config)
        self.assertEqual(with_command["command"], ["/other"])
        self.assertNotIn("args", with_command)

    def test_c8s_carve_out_matches_cds(self):
        core = {GEN.split_image(CORE)[1]}
        self.assertTrue(GEN.is_carved_out({"image": CORE, "command": ["/c8s"]}, core))
        self.assertFalse(GEN.is_carved_out({"image": CORE, "command": ["/other"]}, core))
        self.assertFalse(GEN.is_carved_out({"image": IMAGE, "command": ["/c8s"]}, core))

    def test_new_c8s_retains_authored_attestation_and_proxy_containers(self):
        core = {GEN.split_image(CORE)[1]}
        for mode in ("cds-attest", "allowlist-proxy", "cds", "get-cert"):
            container = {"name": "authored", "image": CORE, "command": ["/c8s"], "args": [mode]}
            self.assertFalse(GEN.is_carved_out(container, core, "v0.44.5-beta.1"))
        cert = {"name": "c8s-cert", "image": CORE, "command": ["/c8s"], "args": ["get-cert"]}
        self.assertTrue(GEN.is_carved_out(cert, core, "v0.41.0"))
        self.assertFalse(GEN.is_carved_out({**cert, "args": ["cds-attest"]}, core, "v0.41.0"))

    def test_seeded_c8s_mirrors_the_chart_seed(self):
        # From c8s v0.47.0 the chart seed names one pinned entry per component
        # shape and the router pod; any other core entry beside it leaves
        # args, mounts or env any, which strict lint refuses.
        shape = {"label": CORE, "initContainers": [], "containers": [{
            "digest": GEN.split_image(CORE)[1], "image": CORE,
            "command": {"policy": "exact", "argv": ["/c8s"]}, "args": {"policy": "exact", "argv": ["cds"]},
            "mounts": {"policy": "exact", "rules": []}, "env": {"policy": "match", "variables": {}}}]}
        router = {"label": "router", "initContainers": [], "containers": [{
            "digest": "sha256:" + "d" * 64, "image": "docker.io/nginxinc/nginx-unprivileged@sha256:" + "d" * 64,
            "command": {"policy": "exact", "argv": ["/docker-entrypoint.sh", "nginx"]},
            "args": {"policy": "exact", "argv": []}, "mounts": {"policy": "exact", "rules": []},
            "env": {"policy": "match", "variables": {}}}]}
        seed = {"c8s-operator-" + "b" * 12 + "-01234567": shape, "c8s-router-" + "e" * 12: router}
        configs = {CORE: {"entrypoint": ["/c8s"]}}
        entries = GEN.core_entries([CORE], seed)
        self.assertEqual(entries, seed)
        self.assertIsNot(entries["c8s-router-" + "e" * 12], router)
        # The node's own images run outside the chart, never as pods: the seed
        # binds no entry to them and they get none.
        volumed = "ghcr.io/confidential-dot-ai/volumed@sha256:" + "a" * 64
        self.assertEqual(GEN.core_entries([CORE, volumed], seed), seed)
        # A shape may pin the container's own command, which extends the
        # entrypoint or replaces it (the c8s v0.66.0+ router reload script);
        # a shape without an exact command pin is refused.
        for argv in (["/c8s", "get-cert"], ["/bin/sh", "/usr/lib/c8s/router-nginx/reload.sh"]):
            extended = copy.deepcopy(seed)
            extended["c8s-operator-" + "b" * 12 + "-01234567"]["containers"][0]["command"]["argv"] = argv
            self.assertEqual(GEN.core_entries([CORE], extended), extended)
        wrong = copy.deepcopy(seed)
        wrong["c8s-operator-" + "b" * 12 + "-01234567"]["containers"][0]["command"] = {"policy": "any"}
        with self.assertRaisesRegex(GEN.GenerationError, "component command pin"):
            GEN.core_entries([CORE], wrong)
        # The manifest contract expects exactly the seed's names.
        policy = {"workloads": []}
        REN.require_allowlist_contract({"workloads": seed}, policy, [CORE], [], configs, "v0.47.0", core_seed=seed)
        with self.assertRaisesRegex(REN.ManifestError, "entries differ"):
            REN.require_allowlist_contract({"workloads": {**seed, "extra": shape}}, policy, [CORE], [], configs,
                                          "v0.47.0", core_seed=seed)

    def test_core_seed_record_cannot_use_another_source_or_image_set(self):
        spec = {"release": "v0.59.1", "sourceCommit": "a" * 40, "coreImages": [CORE]}
        record = {"sourceCommit": spec["sourceCommit"], "coreImages": [CORE],
                  "allowlist": {"schema": "c8s.allowlist/v1", "workloads": {}}}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(GEN, "ROOT", Path(directory)):
            path = Path(directory) / "release/inputs/c8s-seeds" / (spec["sourceCommit"] + ".json")
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(record))
            self.assertEqual(GEN.core_seed(spec), {})
            for field, value in (("sourceCommit", "b" * 40), ("coreImages", [])):
                path.write_text(json.dumps({**record, field: value}))
                with self.assertRaisesRegex(GEN.GenerationError, "differ from the release pins"):
                    GEN.core_seed(spec)

    def test_without_a_record_there_is_no_core_seed(self):
        spec = {"release": "v0.99.29", "sourceCommit": "a" * 40, "coreImages": [CORE]}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(GEN, "ROOT", Path(directory)), \
                self.assertRaisesRegex(GEN.GenerationError, "no C8s seed record"):
            GEN.core_seed(spec)

    def test_the_seed_record_must_be_the_render_of_the_pinned_cli(self):
        operator = "ghcr.io/confidential-dot-ai/c8s-operator@sha256:" + "1" * 64
        mesh = "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:" + "2" * 64
        seed = {"schema": "c8s.allowlist/v1", "workloads": {"c8s-router": {"containers": [{"digest": "sha256:" + "1" * 64}]}}}
        spec = {"release": "v0.99.29", "sourceCommit": "a" * 40, "coreImages": [operator, mesh]}
        record = {"sourceCommit": "a" * 40, "coreImages": [operator, mesh], "hardwarePlatform": "tdx",
                  "kubeVersion": "v1.36.4", "helmVersion": "v3.14.4", "allowlist": seed}
        rendered, commands = {}, []

        def run(command, **_kwargs):
            commands.append(command)
            if command[0] == "helm":
                return b"v3.14.4"
            output = Path(command[command.index("--output-dir") + 1])
            (output / "allowlist-seed.json").write_text(json.dumps(rendered))
            return b""

        cases = {
            "identical render": (seed, record, None),
            "one argv edited in the record": (
                seed, {**record, "allowlist": {**seed, "workloads": {"c8s-router": {"containers": [
                    {"digest": "sha256:" + "1" * 64, "command": {"policy": "exact", "argv": ["/c8s"]}}]}}}},
                "differs from the render"),
            "record without its inputs": (seed, {k: v for k, v in record.items() if k != "helmVersion"},
                                          "names no helmVersion"),
            "another Helm": (seed, {**record, "helmVersion": "v3.16.3"}, "Helm v3.16.3"),
        }
        for name, (render, value, error) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(GEN, "ROOT", Path(directory)), mock.patch.object(GEN, "run", side_effect=run), \
                    mock.patch.object(GEN, "canonicalize", side_effect=lambda document, _tool: json.dumps(document).encode()):
                rendered.clear()
                rendered.update(render)
                path = Path(directory) / "release/inputs/c8s-seeds" / (spec["sourceCommit"] + ".json")
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps(value))
                if error is None:
                    GEN.verify_core_seed(Path("c8s"), None, spec)
                else:
                    with self.assertRaisesRegex(GEN.GenerationError, error):
                        GEN.verify_core_seed(Path("c8s"), None, spec)
        render = next(command for command in reversed(commands) if command[0] == "c8s")
        for flag, value in (("--hardware-platform", "tdx"), ("--kube-version", "v1.36.4"),
                            ("--image-digest", "sha256:" + "1" * 64), ("--armtls-mesh-image-digest", "sha256:" + "2" * 64)):
            self.assertEqual(render[render.index(flag) + 1], value)

    def test_the_render_fails_when_the_seed_record_is_not_the_render(self):
        checked = []

        def verify(c8s, tool, pins):
            checked.append((c8s, pins["sourceCommit"]))
            raise REN.ALLOWLIST_GENERATOR["GenerationError"]("the C8s seed record differs from the render")

        with self.assertRaisesRegex(REN.ManifestError, "differs from the render"):
            render_deployment(verify_core_seed=verify)
        self.assertEqual(checked, [(Path("c8s"), MAN.read_spec()["c8s"]["sourceCommit"])])

    def test_the_c8s_cli_must_be_built_from_the_pinned_commit(self):
        commit, release = "a" * 40, "v0.99.29"
        path = f"\tpath\t{GEN.C8S_MODULE}\n"

        def built(*lines):
            return ("c8s: go1.25.0\n" + path + "".join(f"\t{line}\n" for line in lines)).encode()

        cases = {
            "checkout at the commit": (built(f"mod\t{GEN.C8S_ROOT_MODULE}\t(devel)\t", f"build\tvcs.revision={commit}",
                                             "build\tvcs.modified=false"), True),
            "checkout at another commit": (built(f"mod\t{GEN.C8S_ROOT_MODULE}\t(devel)\t", f"build\tvcs.revision={'b' * 40}",
                                                 "build\tvcs.modified=false"), False),
            "modified checkout": (built(f"build\tvcs.revision={commit}", "build\tvcs.modified=true"), False),
            "no VCS stamp": (built(f"mod\t{GEN.C8S_ROOT_MODULE}\t(devel)\t"), False),
            "module build of the release": (built(f"mod\t{GEN.C8S_ROOT_MODULE}\t{release}\th1:x="), True),
            "module build of another tag": (built(f"mod\t{GEN.C8S_ROOT_MODULE}\tv0.99.30\th1:x="), False),
            "ldflags version only": (built(f"build\t-ldflags=\"-X {GEN.C8S_ROOT_MODULE}/internal/version.Version={commit}\""),
                                     False),
        }
        no_signed_cli = mock.patch.object(GEN, "signed_c8s_cli", side_effect=GEN.GenerationError("no statement"))
        for name, (info, accepted) in cases.items():
            with self.subTest(name), mock.patch.object(GEN, "run", return_value=info), no_signed_cli:
                if accepted:
                    GEN.verify_c8s_binary(Path("c8s"), commit, release)
                else:
                    with self.assertRaisesRegex(GEN.GenerationError, "not built from the pinned"):
                        GEN.verify_c8s_binary(Path("c8s"), commit, release)
        with mock.patch.object(GEN, "run", return_value=b"helm: go1.22\n\tpath\thelm.sh/helm/v3/cmd/helm\n"), \
                self.assertRaisesRegex(GEN.GenerationError, "not the c8s command"):
            GEN.verify_c8s_binary(Path("helm"), commit, release)

    def test_the_c8s_cli_of_the_signed_release_statement_is_accepted(self):
        commit, release = "a" * 40, "v0.101.5"
        release_module = sys.modules["c8s_release"]
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "c8s-linux-amd64"
            binary.write_bytes(b"signed c8s cli")
            digest = release_module.file_sha256(binary)
            statement = {"repository": "confidential-dot-ai/C8s", "tag": release, "commit": commit,
                         "cli": {"linux-amd64": {"asset": "c8s-linux-amd64", "sha256": digest}}}
            calls = []

            def fake(cosign_ok=True, signed=None):
                def run(argv, **_kwargs):
                    calls.append(argv)
                    if argv[:3] == ["gh", "release", "download"]:
                        target = Path(argv[argv.index("--dir") + 1])
                        (target / "release-statement.json").write_text(json.dumps(signed or statement))
                        (target / "release-statement.sigstore.json").write_text("{}")
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if argv[1] == "verify-blob":
                        self.assertIn("https://github.com/confidential-dot-ai/C8s/.github/workflows/semver-tag.yml"
                                      "@refs/heads/main", argv)
                        return subprocess.CompletedProcess(argv, 0 if cosign_ok else 1, "", "bad signature")
                    raise AssertionError(argv)
                return run

            def verify(path, *, run, release=release, commit=commit):
                original = release_module.signed_cli
                def signed_cli(tag, sha, target_dir, **kwargs):
                    return original(tag, sha, target_dir, run=run, cosign="cosign", target="linux-amd64",
                                    allow_beta=kwargs.get("allow_beta", False))
                with mock.patch.object(GEN, "run", side_effect=GEN.GenerationError("no build info")), \
                        mock.patch.object(GEN.c8s_releases, "signed_cli", side_effect=signed_cli):
                    GEN.verify_c8s_binary(path, commit, release)

            verify(binary, run=fake())
            self.assertTrue(any(argv[1:2] == ["verify-blob"] for argv in calls))
            tampered = Path(directory) / "tampered"
            tampered.write_bytes(b"other c8s cli")
            with self.assertRaisesRegex(GEN.GenerationError, "SHA-256 differs"):
                verify(tampered, run=fake())
            with self.assertRaisesRegex(GEN.GenerationError, "release signature does not verify"):
                verify(binary, run=fake(cosign_ok=False))
            with self.assertRaisesRegex(GEN.GenerationError, "does not name"):
                verify(binary, run=fake(), release="v0.101.4")
            with self.assertRaisesRegex(GEN.GenerationError, "does not name commit"):
                verify(binary, run=fake(), commit="b" * 40)
            with self.assertRaisesRegex(GEN.GenerationError, "names no c8s CLI"):
                verify(binary, run=fake(signed={k: v for k, v in statement.items() if k != "cli"}))

    def test_process_contract_accepts_canonical_order_but_refuses_duplicates_and_changes(self):
        main = {"name": "main", "image": IMAGE, "command": ["/entry"], "args": ["--x"]}
        sidecar = {"name": "cds-attest", "image": CORE, "command": ["/c8s"], "args": ["cds-attest"]}
        document = controller(kind="Deployment", name="worker", containers=[main, sidecar])
        def rule(container):
            return {"digest": container["image"].split("@")[1],
                    "command": {"policy": "exact", "argv": container["command"]},
                    "args": {"policy": "exact", "argv": container["args"]}}
        policy = {"workloads": [{"name": "worker", "controller": "Deployment/worker"}]}
        entry = {"containers": [rule(sidecar), rule(main)]}
        allowlist = {"workloads": {"worker": entry}}
        REN.require_allowlist_contract(allowlist, policy, [], [document], {}, "v0.44.6-beta.1")
        for change in (lambda e: e["containers"].append(copy.deepcopy(e["containers"][0])),
                       lambda e: e["containers"][0]["args"]["argv"].append("--unreviewed")):
            changed = copy.deepcopy(allowlist)
            change(changed["workloads"]["worker"])
            with self.assertRaisesRegex(REN.ManifestError, "process differs"):
                REN.require_allowlist_contract(changed, policy, [], [document], {}, "v0.44.6-beta.1")

    def test_beta_release_uses_its_base_version_for_admission_rules(self):
        self.assertTrue(GEN.c8s_at_least("v0.44.0-beta.1", (0, 44, 0)))
        self.assertFalse(GEN.c8s_at_least("v0.37.0-beta.1", (0, 41, 0)))
        with self.assertRaises(GEN.GenerationError):
            GEN.c8s_at_least("main", (0, 44, 0))


class AcceptedFindingTests(unittest.TestCase):
    LINE = ('error: workload "{entry}" container sha256:' + "c" * 64 + ' pins PATH to a search path '
            'overlapping host mount "{path}"; operator-supplied content could be loaded as code')

    def lint_with(self, lines, accepted, code=1):
        class Result:
            returncode = code
            stdout = ("\n".join(lines) + "\n").encode()
            stderr = b""
        original = GEN.subprocess.run
        GEN.subprocess.run = lambda *a, **k: Result()
        try:
            GEN.lint(Path("c8s"), Path("allowlist.json"), accepted)
        finally:
            GEN.subprocess.run = original

    def key(self, entry, path):
        return (entry, "search-path-overlaps-mount", "PATH", "host", path)

    def test_accepted_findings_pass(self):
        self.lint_with([self.LINE.format(entry="w", path="/usr/bin/a"), "1 lint error(s)"], {self.key("w", "/usr/bin/a")})

    def test_a_new_finding_fails(self):
        with self.assertRaisesRegex(GEN.GenerationError, "not accepted"):
            self.lint_with([self.LINE.format(entry="w", path="/usr/bin/b"), "1 lint error(s)"], {self.key("w", "/usr/bin/a")})

    def test_a_vanished_finding_fails(self):
        with self.assertRaisesRegex(GEN.GenerationError, "no longer appears"):
            self.lint_with([], {self.key("w", "/usr/bin/a")}, code=0)

    def test_an_unknown_line_fails(self):
        with self.assertRaisesRegex(GEN.GenerationError, "not an accepted finding"):
            self.lint_with(["warning: something else", self.LINE.format(entry="w", path="/usr/bin/a"), "2 lint warning(s) with --strict"],
                           {self.key("w", "/usr/bin/a")})


class FrameworkReleaseTests(unittest.TestCase):
    def test_signed_beta_version_is_a_valid_release_input(self):
        spec = MAN.read_spec()
        for version in ('v0.37.0-beta.1', 'v0.37.0'):
            MAN.validate_spec({**spec, 'c8s': {**spec['c8s'], 'release': version}})
        for version in ('v0.37.0-beta.0', 'v0.37.0-beta.01', 'v0.37.0-rc.1', 'v0.72.1-0.20261023005616-90bd65abd955'):
            with self.assertRaisesRegex(MAN.ManifestError, 'c8s.release'):
                MAN.validate_spec({**spec, 'c8s': {**spec['c8s'], 'release': version}})

    def test_the_spec_holds_only_c8s_and_images(self):
        spec = MAN.read_spec()
        for key, value in (("version", "v0.14.0"), ("model", {}), ("publicHostnames", ["api.example.invalid"])):
            with self.subTest(key=key), self.assertRaisesRegex(MAN.ManifestError, "exactly c8s and images"):
                MAN.validate_spec({**spec, key: value})

    def test_the_spec_names_each_image_correctly(self):
        spec = MAN.read_spec()
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        for images, message in (
            ({**spec["images"], "gateway": gateway + "@sha256:" + "1" * 64}, "pins a digest"),
            ({**spec["images"], "telemetryCollector": "docker.io/otel/collector:latest"}, "not digest-pinned"),
            ({**spec["images"], "c8sOperator": "ghcr.io/confidential-dot-ai/c8s-operator@sha256:" + "1" * 64},
             "not one of the c8s core images"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(MAN.ManifestError, message):
                MAN.validate_spec({**spec, "images": images})

    def test_the_tag_names_the_release(self):
        files = build_framework(publication(published_release_images()), tag="v0.14.9")
        manifest = json.loads(files["release-bundle.json"])
        self.assertEqual(manifest["release"], {"name": "v0.14.9"})
        for tag in ("v0.14.9-rc.1", "v0.14.9-staging", "staging"):
            with self.subTest(tag=tag), self.assertRaisesRegex(MAN.ManifestError, "vX.Y.Z"):
                build_framework(publication(published_release_images()), tag=tag)

    def test_the_framework_manifest_names_the_software_and_no_deployment_value(self):
        files = build_framework(publication(published_release_images()))
        self.assertEqual(sorted(files), ["cds-manifest.json", "confidential-inference-0.17.0.tgz", "release-bundle.json"])
        manifest = json.loads(files["release-bundle.json"])
        spec = MAN.read_spec()
        self.assertEqual(manifest["schema"], "confidential.ai/release-manifest/v2")
        self.assertEqual(manifest["releaseTrust"], {
            "policyPath": "release/trust/release-signing-policy.json",
            "policySha256": MAN.sha256((ROOT / "release/trust/release-signing-policy.json").read_bytes()),
            "signatureType": "sigstore-keyless",
        })
        self.assertEqual(manifest["source"], {"repository": REPOSITORY, "commit": "d" * 40})
        self.assertEqual(manifest["imagePublication"]["sourceCommit"], "b" * 40)
        self.assertEqual(manifest["images"], RELEASE_IMAGES)
        self.assertEqual(manifest["c8s"], {"release": spec["c8s"]["release"], "sourceCommit": spec["c8s"]["sourceCommit"],
                                           "coreImages": sorted(spec["c8s"]["coreImages"]),
                                           "seedImages": MAN.seed_images(spec["c8s"])})
        # The C8s v0.99.29 seed names the operator, mesh and router images, all C8s core images.
        self.assertTrue(manifest["c8s"]["seedImages"])
        self.assertLessEqual(set(manifest["c8s"]["seedImages"]), set(spec["c8s"]["coreImages"]))
        self.assertEqual(manifest["cdsImage"]["reference"],
                         spec["c8s"]["cdsImage"]["reference"] + "@" + spec["c8s"]["cdsImage"]["digest"])

        self.assertEqual(manifest["chart"], {
            "name": "confidential-inference", "version": "0.17.0",
            "sha256": MAN.chart_identity(MAN.CHART)["treeSha256"],
            "archiveSha256": MAN.sha256(files["confidential-inference-0.17.0.tgz"]),
            "reference": "ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:0.17.0",
        })
        for key in ("allowlist", "releaseValues", "profileValues", "model", "publicHostnames", "transition"):
            self.assertNotIn(key, manifest)
        self.assertNotIn("environment", manifest["release"])

    def test_every_digest_of_a_rendered_allowlist_is_named_by_the_framework_release(self):
        manifest = framework_manifest()
        named = {image.split("@")[1] for image in [*manifest["images"].values(), *manifest["c8s"]["coreImages"],
                                                     *manifest["c8s"]["seedImages"]]}
        allowlist = json.loads(render_deployment()["allowlist.json"])
        live = {container["digest"] for entry in allowlist["workloads"].values()
                for container in entry.get("initContainers", []) + entry.get("containers", [])}
        self.assertEqual(live - named, set())

    def test_image_source_boundary_allows_only_later_non_image_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            gateway = repo / "images/gateway/Dockerfile"
            gateway.parent.mkdir(parents=True)
            gateway.write_text("FROM scratch\n")
            spec = repo / "release/spec.yaml"
            spec.parent.mkdir(parents=True)
            spec.write_text("version: first\n")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "image source"], cwd=repo, check=True)
            image_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            spec.write_text("version: pinned\n")
            subprocess.run(["git", "commit", "-qam", "pin release"], cwd=repo, check=True)
            release_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            MAN.verify_image_source_boundary(image_source, release_source, repo)
            gateway.write_text("FROM scratch\nLABEL changed=yes\n")
            subprocess.run(["git", "commit", "-qam", "change image"], cwd=repo, check=True)
            changed_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            with self.assertRaisesRegex(MAN.ManifestError, "gateway"):
                MAN.verify_image_source_boundary(image_source, changed_source, repo)

    def test_image_source_boundary_rejects_a_changed_selector(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            selector = repo / "scripts/affected-release-images.py"
            selector.parent.mkdir(parents=True)
            selector.write_text("selector = 1\n")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "image source"], cwd=repo, check=True)
            image_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            selector.write_text("selector = 2\n")
            subprocess.run(["git", "commit", "-qam", "change selector"], cwd=repo, check=True)
            release_source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            # The release commit's selector re-reads the whole diff, so a
            # change of the selector alone keeps the image evidence valid.
            # Staging stopped on confidential-inference#117 without this.
            MAN.verify_image_source_boundary(image_source, release_source, repo)

    def base_release(self) -> dict:
        base = framework_manifest()
        base["release"]["name"] = "v0.16.9"
        base["source"]["commit"] = "c" * 40
        return base

    def test_an_unchanged_image_keeps_the_digest_of_the_signed_base_release(self):
        sglang = "ghcr.io/confidential-dot-ai/confidential-inference/sglang"
        evidence = publication({sglang: published_release_images()[sglang]}, base_ref="v0.16.9")
        manifest = json.loads(build_framework(evidence, self.base_release())["release-bundle.json"])
        self.assertEqual(manifest["images"]["gateway"], RELEASE_IMAGES["gateway"])
        self.assertEqual(manifest["imagePublication"]["images"], {sglang: published_release_images()[sglang]})

    def test_a_release_of_the_earlier_format_is_a_valid_base(self):
        # The published v0.15.15 manifest, a v1 release with a -staging-free tag.
        v1 = json.loads((FIXTURES / "v0.15.15-release-manifest.json").read_text())
        evidence = publication({}, base_ref="v0.15.15", base_commit=v1["source"]["commit"])
        images = self.base_images(evidence, v1)
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        self.assertEqual(images[gateway], v1["images"]["gateway"].split("@", 1)[1])

    @staticmethod
    def base_with_values(raw: bytes, *, cached: bytes | None = None,
                         signed_values: bool = True) -> dict[str, str]:
        helper = "ghcr.io/confidential-dot-ai/confidential-inference/rollout-client"
        base = {"source": {"commit": "c" * 40}, "images": {}}
        if signed_values:
            base["releaseValues"] = {"sha256": MAN.sha256(raw)}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            if cached is not None:
                (directory / "release-values.yaml").write_bytes(cached)
            with mock.patch.object(MAN, "signed_release", return_value=base), \
                    mock.patch.object(MAN, "changed_paths", return_value=[]), \
                    mock.patch.object(MAN, "fetch", return_value=raw) as fetch:
                result = MAN.base_release_images(publication({}, base_ref="v0.14.1"),
                                                directory, required_images={helper})
                if cached is None and signed_values:
                    fetch.assert_called_once_with(
                        f"{REPOSITORY}/releases/download/v0.14.1/release-values.yaml")
                else:
                    fetch.assert_not_called()
                return result

    def test_an_earlier_release_supplies_an_omitted_helper_from_hash_bound_values(self):
        reference = RELEASE_IMAGES["rolloutClient"]
        raw = json.dumps({"images": {"rolloutClient": reference}}).encode()
        self.assertEqual(self.base_with_values(raw), dict([reference.split("@", 1)]))

    def test_base_values_hash_is_checked_even_for_a_cached_asset(self):
        raw = json.dumps({"images": {"rolloutClient": RELEASE_IMAGES["rolloutClient"]}}).encode()
        with self.assertRaisesRegex(MAN.ManifestError, "values differ from its signed manifest"):
            self.base_with_values(raw, cached=b"untrusted values")

    def test_base_values_cannot_choose_between_conflicting_helper_digests(self):
        helper = RELEASE_IMAGES["rolloutClient"].split("@", 1)[0]
        raw = json.dumps({"images": {"one": helper + "@sha256:" + "1" * 64,
                                     "two": helper + "@sha256:" + "2" * 64}}).encode()
        with self.assertRaisesRegex(MAN.ManifestError, "ambiguous component image digests"):
            self.base_with_values(raw)

    def test_unbound_values_do_not_supply_a_missing_helper(self):
        raw = json.dumps({"images": {"rolloutClient": RELEASE_IMAGES["rolloutClient"]}}).encode()
        self.assertEqual(self.base_with_values(raw, signed_values=False), {})

    def test_the_base_release_must_match_the_publication(self):
        base = self.base_release()
        evidence = publication({}, base_ref="v0.16.9")
        for value, message in (
            ({**base, "release": {**base["release"], "name": "v0.16.8"}}, "different release"),
            ({**base, "source": {**base["source"], "commit": "e" * 40}}, "base commit"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(MAN.ManifestError, message):
                self.base_images(evidence, value)

    def test_the_build_downloads_the_base_release_that_the_evidence_names(self):
        urls = []

        def fetch(url):
            urls.append(url)
            return url.encode()

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(MAN, "fetch", side_effect=fetch):
            directory = Path(temporary) / "base"
            self.assertEqual(MAN.base_release_images(publication({}), directory), {})
            self.assertEqual(urls, [])
            paths = MAN.download_base_release("v0.14.1-staging", directory)
            release = f"{REPOSITORY}/releases/download/v0.14.1-staging"
            self.assertEqual(urls, [f"{release}/release-bundle.json", f"{release}/release-bundle.sigstore.json"])
            self.assertEqual([path.read_text() for path in paths], urls)
            MAN.download_base_release("v0.14.1-staging", directory)
            self.assertEqual(len(urls), 2)

    def test_the_download_sends_the_token_to_github_only(self):
        with mock.patch.dict(MAN.os.environ, {"GH_TOKEN": "token"}), \
                mock.patch.object(MAN.urllib.request, "urlopen") as urlopen:
            urlopen.return_value.__enter__.return_value.read.return_value = b"{}"
            self.assertEqual(MAN.fetch(f"{REPOSITORY}/releases/download/v1.0.0/release-bundle.json"), b"{}")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.unredirected_hdrs, {"Authorization": "Bearer token"})
        self.assertNotIn("Authorization", request.headers)

    def test_an_image_changed_after_the_base_needs_a_new_digest(self):
        base = self.base_release()
        evidence = publication({}, base_ref="v0.16.9")
        with self.assertRaisesRegex(MAN.ManifestError, "no new digest: gateway"):
            self.base_images(evidence, base, ["images/gateway/Dockerfile"])
        images = self.base_images(evidence, base, ["docs/threat-model.md"])
        self.assertEqual(images["ghcr.io/confidential-dot-ai/confidential-inference/gateway"],
                         RELEASE_IMAGES["gateway"].split("@", 1)[1])

    @staticmethod
    def base_images(evidence: dict, base: dict, changed: list[str] | None = None) -> dict[str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_release(directory, base)
            with mock.patch.object(MAN, "changed_paths", return_value=changed or []), \
                    mock.patch.object(MAN.release_signature, "verify_release_signature") as verify, \
                    mock.patch.object(MAN.shutil, "which", return_value="/usr/bin/cosign"):
                images = MAN.base_release_images(evidence, directory)
                verify.assert_called_once_with(directory / "release-bundle.json",
                                               directory / "release-bundle.sigstore.json",
                                               Path("/usr/bin/cosign").resolve(), 60)
                return images

    def test_release_images_take_repository_digests_only_from_evidence(self):
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        other = "docker.io/library/busybox@sha256:" + "1" * 64
        images = {"gateway": gateway, "other": other}
        evidence = publication({gateway: "sha256:" + "2" * 64})
        self.assertEqual(MAN.release_images(images, evidence, {}),
                         {"gateway": f"{gateway}@sha256:{'2' * 64}", "other": other})
        self.assertEqual(MAN.release_images(images, publication({}), {gateway: "sha256:" + "3" * 64})["gateway"],
                         f"{gateway}@sha256:{'3' * 64}")
        with self.assertRaisesRegex(MAN.ManifestError, "neither"):
            MAN.release_images(images, publication({}), {})

    def test_the_repository_holds_no_digest_of_a_repository_image(self):
        for key, value in MAN.read_spec()["images"].items():
            if value.startswith(SPEC.REPOSITORY_IMAGES):
                with self.subTest(key=key):
                    self.assertNotIn("@", value)
        configs = json.loads(SPEC.IMAGE_CONFIG.read_text())
        self.assertFalse([image for image in configs if image.startswith(SPEC.REPOSITORY_IMAGES)])
        self.assertFalse((ROOT / "release/values.yaml").exists())
        self.assertFalse((ROOT / "release/profiles.json").exists())

    def test_manifest_refuses_publication_evidence_for_another_digest(self):
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        with self.assertRaisesRegex(MAN.ManifestError, "differs from the release"):
            MAN.publication_binding(b"{}", publication({gateway: "sha256:" + "0" * 64}),
                                    {"gateway": f"{gateway}@sha256:{'1' * 64}"})

    def test_manifest_records_a_published_image_outside_the_application_chart(self):
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        maintenance = "ghcr.io/confidential-dot-ai/confidential-inference/maintenance-gateway"
        result = MAN.publication_binding(b"{}", publication({maintenance: "sha256:" + "2" * 64}),
                                         {"gateway": f"{gateway}@sha256:{'1' * 64}"})
        self.assertEqual(result["images"][maintenance], "sha256:" + "2" * 64)

    def test_manifest_refuses_publication_outside_the_release_registry(self):
        unknown = publication({"ghcr.io/confidential-dot-ai/confidential-inference/unknown": "sha256:" + "1" * 64})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "publication.json"
            path.write_text(json.dumps(unknown))
            with self.assertRaisesRegex(MAN.ManifestError, "outside the release image registry"):
                MAN.read_publication(path)

    def test_the_source_lock_pins_the_spec_commit(self):
        lock = json.loads(LOCK.read_text())
        spec = MAN.read_spec()
        entry = MAN.source_lock_entry(lock, spec["c8s"]["sourceCommit"])
        self.assertEqual(entry["tag"], spec["c8s"]["release"])
        self.assertEqual(entry["nodeImage"], spec["c8s"]["nodeImage"]["reference"] + "@" + spec["c8s"]["nodeImage"]["digest"])

    def test_the_node_manifest_matches_the_pinned_artifact_layer(self):
        data = SPEC.NODE_MANIFEST.read_bytes()
        self.assertEqual(MAN.sha256(data), MAN.read_spec()["c8s"]["nodeManifestArtifact"]["manifestJson"])
        NODE.check_measurements(json.loads(data))

    def test_the_cds_manifest_matches_the_pinned_artifact_layer(self):
        spec = MAN.read_spec()
        data = SPEC.CDS_MANIFEST.read_bytes()
        self.assertEqual(MAN.sha256(data), spec["c8s"]["cdsManifestArtifact"]["manifestJson"])
        NODE.check_measurements(json.loads(data))
        self.assertEqual(MAN.cds_image(SPEC.CDS_MANIFEST, spec), {
            "reference": spec["c8s"]["cdsImage"]["reference"] + "@" + spec["c8s"]["cdsImage"]["digest"],
            "manifestSha256": MAN.sha256(data)})

    def test_the_spec_pins_the_cds_guest_image_and_its_manifest_artifact(self):
        spec = copy.deepcopy(MAN.read_spec())
        cds, artifact = spec["c8s"]["cdsImage"], spec["c8s"]["cdsManifestArtifact"]
        for key in ("cdsImage", "cdsManifestArtifact"):
            with self.subTest(missing=key), self.assertRaisesRegex(MAN.ManifestError, f"c8s.{key} needs"):
                MAN.validate_spec({**spec, "c8s": {k: v for k, v in spec["c8s"].items() if k != key}})
        with self.assertRaisesRegex(MAN.ManifestError, "cdsManifestArtifact needs"):
            MAN.validate_spec({**spec, "c8s": {**spec["c8s"], "cdsManifestArtifact": {**artifact, "manifestJson": "x"}}})
        with self.assertRaisesRegex(MAN.ManifestError, "cdsImage needs"):
            MAN.validate_spec({**spec, "c8s": {**spec["c8s"], "cdsImage": {**cds, "digest": "latest"}}})

    def test_the_release_carries_the_cds_manifest_it_binds(self):
        files = build_framework(publication(published_release_images()))
        manifest = json.loads(files["release-bundle.json"])
        self.assertEqual(files["cds-manifest.json"], SPEC.CDS_MANIFEST.read_bytes())
        self.assertEqual(MAN.sha256(files["cds-manifest.json"]), manifest["cdsImage"]["manifestSha256"])
        spec = MAN.read_spec()["c8s"]
        self.assertEqual(manifest["cdsImage"]["reference"], spec["cdsImage"]["reference"] + "@" + spec["cdsImage"]["digest"])

    def test_a_changed_cds_manifest_stops_the_build(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cds-manifest.json"
            path.write_bytes(SPEC.CDS_MANIFEST.read_bytes() + b" ")
            with self.assertRaisesRegex(MAN.ManifestError, "differs from c8s.cdsManifestArtifact.manifestJson"):
                MAN.cds_image(path, MAN.read_spec())

    def test_fetch_needs_the_node_and_the_cds_pins_whole(self):
        node = {"nodeImage": {"reference": "ghcr.io/example/worker"},
                "nodeManifestArtifact": {"digest": "sha256:" + "1" * 64}}
        cds = {"cdsImage": {"reference": "ghcr.io/example/cds"}, "cdsManifestArtifact": {"digest": "sha256:" + "2" * 64}}
        cases = {
            "node and CDS": ({**node, **cds}, None),
            "node only": (node, "pins cdsImage and cdsManifestArtifact"),
            "CDS image only": ({"cdsImage": cds["cdsImage"]}, "no c8s node image"),
            "node and the CDS image without its artifact": ({**node, "cdsImage": cds["cdsImage"]},
                                                            "pins cdsImage and cdsManifestArtifact"),
            "node without its artifact": ({"nodeImage": node["nodeImage"]}, "no c8s node image"),
            "CDS image with a tag": ({**node, **cds, "cdsImage": {"reference": "ghcr.io/example/cds:v1"}},
                                     "cdsImage.reference"),
            "no c8s": (None, "no c8s node image"),
        }
        for name, (c8s, error) in cases.items():
            with self.subTest(name):
                spec = {"c8s": c8s} if c8s is not None else {}
                if error is None:
                    self.assertIs(NODE.read_spec(spec), spec)
                else:
                    with self.assertRaisesRegex(NODE.FetchError, error):
                        NODE.read_spec(spec)

    def test_fetch_check_compares_the_node_and_the_cds_manifest(self):
        node, cds = SPEC.NODE_MANIFEST.read_bytes(), SPEC.CDS_MANIFEST.read_bytes()

        def fetch(_spec, keys=NODE.NODE):
            return (cds, {}) if keys == NODE.CDS else (node, {})

        for name, (node_file, cds_file, status) in {
            "both match": (node, cds, 0), "the CDS manifest differs": (node, cds + b" ", 1),
            "the node manifest differs": (node + b" ", cds, 1),
        }.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as directory, \
                    mock.patch.object(NODE, "fetch", side_effect=fetch), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                paths = Path(directory) / "node.json", Path(directory) / "cds.json"
                paths[0].write_bytes(node_file)
                paths[1].write_bytes(cds_file)
                argv = ["fetch-node-manifest.py", "--check", "--output", str(paths[0]), "--cds-output", str(paths[1])]
                with mock.patch.object(sys, "argv", argv):
                    self.assertEqual(NODE.main(), status, stderr.getvalue())
                self.assertEqual((paths[0].read_bytes(), paths[1].read_bytes()), (node_file, cds_file))

    def test_the_schema_refuses_deployment_values(self):
        schema = json.loads((ROOT / "api/release-manifest-v2.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        self.assertFalse(schema["additionalProperties"])
        for forbidden in ("meshCa", "target", "allowlist", "releaseValues", "profileValues", "model",
                          "publicHostnames", "transition"):
            self.assertNotIn(forbidden, schema["properties"])
        self.assertFalse(schema["properties"]["release"]["additionalProperties"])
        self.assertEqual(set(schema["properties"]["release"]["properties"]), {"name"})
        manifest = framework_manifest()
        for key, value in (("allowlist", {}), ("model", {})):
            with self.subTest(key=key), self.assertRaises(jsonschema.ValidationError):
                jsonschema.validate({**manifest, key: value}, schema)

    def test_a_signed_manifest_with_the_old_lock_path_still_validates(self):
        # The published v0.15.15 manifest, which names the lock at contracts/.
        signed = json.loads((FIXTURES / "v0.15.15-release-manifest.json").read_text())
        self.assertEqual(signed["sourceLock"]["path"], "contracts/c8s-admission-source-lock.json")
        MAN.release_signature.validate_release_schema(signed)
        moved = copy.deepcopy(signed)
        moved["sourceLock"]["path"] = MAN.SOURCE_LOCK.relative_to(ROOT).as_posix()
        MAN.release_signature.validate_release_schema(moved)

    def test_a_release_of_c8s_v0_99_or_later_must_name_its_cds_image(self):
        schema = json.loads((ROOT / "api/release-manifest-v2.schema.json").read_text())
        rules = {"allOf": schema["allOf"]}
        cds = {"reference": "ghcr.io/confidential-dot-ai/guests/cds@sha256:" + "1" * 64, "manifestSha256": "sha256:" + "2" * 64}
        for release, required in {
            "v0.9.0": False, "v0.98.9": False, "v0.80.10": False,
            "v0.99.0": True, "v0.99.29": True, "v0.99.29-beta.1": True, "v0.100.0": True, "v1.0.0": True,
        }.items():
            with self.subTest(release=release):
                jsonschema.validate({"c8s": {"release": release}, "cdsImage": cds}, rules)
                if required:
                    with self.assertRaises(jsonschema.ValidationError):
                        jsonschema.validate({"c8s": {"release": release}}, rules)
                else:
                    jsonschema.validate({"c8s": {"release": release}}, rules)
        manifest = framework_manifest()
        self.assertIn("cdsImage", manifest)
        jsonschema.validate(manifest, schema)

    def test_a_framework_release_pins_no_dev_c8s_build(self):
        schema = json.loads((ROOT / "api/release-manifest-v2.schema.json").read_text())
        rule = schema["properties"]["c8s"]["properties"]["release"]
        jsonschema.validate("v0.72.0", rule)
        jsonschema.validate("v0.72.0-beta.1", rule)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate("v0.72.1-0.20261023005616-90bd65abd955", rule)


class RenderTests(unittest.TestCase):
    def test_policy_matches_each_rendered_controller_and_workload_identity(self):
        for name, deployment in (("production", PRODUCTION), ("staging", STAGING)):
            policy = REN.read_allowlist_policy(deployment.policy)
            controllers = GEN.controllers(rendered(deployment))
            with self.subTest(deployment=name):
                self.assertEqual(set(controllers), {item["controller"] for item in policy["workloads"]})
                for item in policy["workloads"]:
                    identity = controllers[item["controller"]]["spec"]["template"]["metadata"]["annotations"]["confidential.ai/cw"]
                    self.assertEqual(item["name"], identity)

    def test_the_staging_fixture_is_the_allowlist_that_the_given_c8s_cli_generates(self):
        calls = []

        def generate(_deployment, executable, *_args, **_kwargs):
            calls.append(executable)
            return STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n")

        with mock.patch.dict(REN.ALLOWLIST_GENERATOR, {"generate": generate}):
            files = render_deployment(c8s=Path("/tmp/c8s"), verify_core_seed=lambda *_args: None)
        self.assertEqual(files["allowlist.json"], STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n"))
        self.assertEqual(calls, [Path("/tmp/c8s")])

    def test_the_render_writes_the_allowlist_the_framework_values_and_its_record(self):
        files = render_deployment()
        self.assertEqual(sorted(files), ["allowlist.json", "release-values.yaml", "render.json"])
        self.assertEqual(files["allowlist.json"], STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n"))
        self.assertEqual(yaml.safe_load(files["release-values.yaml"]),
                         {"environment": "staging", "images": RELEASE_IMAGES, "frameworkRelease": {
                             "name": "v0.17.0", "bundleSha256": MAN.sha256(framework_bytes())}})
        record = json.loads(files["render.json"])
        self.assertEqual(record["environment"], "staging")
        self.assertEqual(record["frameworkRelease"], {"name": "v0.17.0", "sourceCommit": "d" * 40,
                                                      "bundleSha256": MAN.sha256(framework_bytes())})
        self.assertEqual([item["path"] for item in record["values"]],
                         ["tests/fixtures/deployments/production-values.yaml",
                          "tests/fixtures/deployments/staging-values.yaml"])
        self.assertEqual(record["allowlistSha256"], MAN.sha256(files["allowlist.json"]))
        self.assertEqual(record["releaseValuesSha256"], MAN.sha256(files["release-values.yaml"]))

    def test_deployment_values_cannot_set_framework_values(self):
        for values, field in (({"images": {"gateway": "example/gateway@sha256:" + "1" * 64}}, "images"),
                              ({"frameworkRelease": {"name": "v9.9.9"}}, "frameworkRelease")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "values.yaml"
                path.write_text(yaml.safe_dump(values))
                deployment = SPEC.Deployment((*STAGING.values_files, path), STAGING.policy, STAGING.accepted_findings)
                with self.assertRaisesRegex(REN.ManifestError, f"sets {field}"):
                    render_deployment(deployment)

    def test_the_render_sets_the_environment_from_its_name(self):
        for name in ("staging", "production", "eu-west-2"):
            with self.subTest(name=name):
                self.assertEqual(yaml.safe_load(REN.release_overlay(framework_manifest(), "sha256:" + "0" * 64,
                                                                    name))["environment"], name)
        for name in ("", "Staging", "-staging", "staging-", "stag_ing", "a" * 64):
            with self.subTest(name=name), self.assertRaisesRegex(REN.ManifestError, "environment name"):
                render_deployment(environment=name)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "values.yaml"
            path.write_text(yaml.safe_dump({"environment": "staging"}))
            deployment = SPEC.Deployment((*STAGING.values_files, path), STAGING.policy, STAGING.accepted_findings)
            with self.assertRaisesRegex(REN.ManifestError,
                                        "sets environment; the render sets it from the environment name"):
                render_deployment(deployment)

    def test_the_chart_can_render_only_framework_images(self):
        manifest = framework_manifest()
        changed = copy.deepcopy(manifest)
        changed["images"]["gateway"] = changed["images"]["gateway"].split("@")[0] + "@sha256:" + "1" * 64
        with mock.patch.object(REN, "release_overlay", return_value=yaml.safe_dump(
                {"environment": "staging", "images": manifest["images"], "frameworkRelease": {
                    "name": "v0.17.0", "bundleSha256": MAN.sha256(framework_bytes())}}).encode()), \
                mock.patch.dict(REN.MAN, {}):
            with self.assertRaisesRegex(REN.ManifestError, "does not name"):
                render_deployment(manifest=changed)

    def test_the_allowlist_names_only_digests_of_the_framework_release(self):
        # The seed entries name only C8s core images, so take one seed image out of both lists.
        changed = framework_manifest()
        for key in ("coreImages", "seedImages"):
            changed["c8s"][key] = [image for image in changed["c8s"][key] if "nginx-unprivileged" not in image]
        with self.assertRaisesRegex(REN.ManifestError, "does not name: \\['sha256:5d8bb943"):
            render_deployment(manifest=changed)

    def test_the_live_allowlist_names_the_framework_release(self):
        allowlist = json.loads(STAGING_ALLOWLIST.read_text())
        gateway = allowlist["workloads"]["gateway"]["containers"][0]
        self.assertEqual(REN.pinned_env(gateway)["CI_FRAMEWORK_RELEASE"], "v0.17.0")
        self.assertEqual(REN.pinned_env(gateway)["CI_FRAMEWORK_RELEASE_BUNDLE_SHA256"], MAN.sha256(framework_bytes()))
        REN.require_release_identity(allowlist, "v0.17.0", MAN.sha256(framework_bytes()))
        with self.assertRaisesRegex(REN.ManifestError, "does not pin the framework release"):
            REN.require_release_identity(allowlist, "v0.17.1", MAN.sha256(framework_bytes()))
        with self.assertRaisesRegex(REN.ManifestError, "does not pin the framework release"):
            REN.require_release_identity(allowlist, "v0.17.0", "sha256:" + "0" * 64)

    def test_the_render_requires_the_checkout_of_the_framework_release(self):
        manifest = framework_manifest()
        with self.assertRaisesRegex(REN.ManifestError, "check out source commit"):
            REN.require_checkout(manifest)

    def test_staging_workers_download_and_verify_the_model_before_the_simulator(self):
        """Staging downloads the model at each start (inference.model.download), as C8s v0.99.29 workers do."""
        values = STAGING.read_values()["inference"]["model"]
        manifest_sha256 = MAN.sha256(values["download"]["manifest"].encode()).removeprefix("sha256:")
        workers = rendered_workers(STAGING)
        self.assertEqual(len(workers), 2)
        for worker in workers:
            pod = worker["spec"]["template"]
            container = pod["spec"]["containers"][0]
            self.assertEqual(container["command"][:2], ["/bin/sh", "-c"])
            self.assertIn(f"--manifest-sha256={manifest_sha256} ", container["command"][2])
            self.assertEqual(container["args"][:3], ["/usr/local/bin/wait-for-model",
                                                     container["args"][1], "--plain-cache"])
            self.assertIn("python3", container["args"])
            self.assertIn("sglang_simulator.simulation.sglang.launch_server", container["args"])
            self.assertNotIn("confidential.ai/c8s-volumes", pod["metadata"]["annotations"])
            self.assertEqual(pod["spec"]["hostAliases"], [{"ip": "192.0.2.20", "hostnames": ["models.example.invalid"]}])
            self.assertEqual(container["resources"]["requests"]["memory"], "16Gi")

        allowlist = json.loads(STAGING_ALLOWLIST.read_text())
        zero_digest = "sha256:" + "0" * 64
        for index, name in enumerate(("inference-worker-0", "inference-worker-1")):
            entry = allowlist["workloads"][name]
            # The download address is the entry's one exit (C8s #1047).
            self.assertEqual(entry["egress"], [{"cidr": "192.0.2.20/32", "port": 443}])
            guarded = [item for item in entry["containers"]
                       if item["command"].get("argv", [""])[0] == "/bin/sh"]
            self.assertEqual(len(guarded), 1)
            policy = guarded[0]
            self.assertEqual(policy["command"]["argv"], workers[index]["spec"]["template"]["spec"]["containers"][0]["command"])
            self.assertEqual(policy["args"]["argv"][0], "/usr/local/bin/wait-for-model")
            self.assertIn("sglang_simulator.simulation.sglang.launch_server", policy["args"]["argv"])
            model = "/mnt/c8s-data/models/" + values["volumeNames"][index]
            # The download volume is writable at the fetch path and read-only at the model path.
            self.assertEqual(policy["mounts"], {"policy": "exact", "rules": [
                {"destination": "/dev/shm", "kind": "emptyDir"},
                {"destination": "/mnt/c8s-data/model-download", "kind": "emptyDir"},
                {"destination": "/mnt/c8s-data/model-manifest", "kind": "data"},
                {"destination": model, "kind": "emptyDir"}]})
        self.assertNotIn(zero_digest, STAGING_ALLOWLIST.read_text())

    @staticmethod
    def expected_file_args(deployment) -> list[list[str]]:
        result = []
        workers = rendered_workers(deployment)
        if not workers:
            raise AssertionError("the deployment must render inference workers")
        for worker in workers:
            container = next(c for c in worker["spec"]["template"]["spec"]["containers"]
                             if c["name"] in ("sglang", "engram-holder", "sglang-pair"))
            args = container["args"]
            if container["name"] == "sglang-pair":
                args = json.loads(args[1])["modelGate"]
            result.append([arg.removeprefix("--expected-file=") for arg in args
                           if arg.startswith("--expected-file=")])
        return result

    def test_workers_check_the_expected_files_map_of_their_values(self):
        for name, deployment in (("production", PRODUCTION), ("staging", STAGING)):
            verification = deployment.read_values()["inference"]["model"]["mountVerification"]
            expected = sorted(f"{item['path']}={item['sha256']}" for item in verification["expectedFileList"])
            for arguments in self.expected_file_args(deployment):
                with self.subTest(deployment=name):
                    self.assertEqual(arguments, expected)

    def test_staging_policy_uses_its_exact_render_and_allowlist_namespace(self):
        spec = MAN.read_spec()
        policy = REN.read_allowlist_policy(STAGING.policy)
        core = spec["c8s"]["coreImages"]
        documents = rendered(STAGING)
        allowlist = json.loads(STAGING_ALLOWLIST.read_text())
        configs = {**json.loads(SPEC.IMAGE_CONFIG.read_text()), **REPOSITORY_CONFIGS}
        # Use the real CDS process ordering that generation writes.
        allowlist = json.loads(GEN.canonicalize(allowlist, None))
        contract = functools.partial(REN.require_allowlist_contract, policy=policy, core_images=core,
                                     documents=documents, image_configs=configs,
                                     c8s_release=GEN.feature_release(spec["c8s"]), core_seed=GEN.core_seed(spec["c8s"]))
        contract(allowlist)
        router = next(item for item in documents if item.get("kind") == "Deployment"
                      and item.get("metadata", {}).get("name") == "sglang-router")
        args = router["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertEqual(args[:3], ["--worker-urls", "http://inference-worker-0-0.inference-workers:30000",
                                    "http://inference-worker-1-0.inference-workers:30000"])
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"].pop("inference-worker-1")
        with self.assertRaisesRegex(REN.ManifestError, "entries differ"):
            contract(changed)
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"]["sglang-router"]["containers"][0]["args"]["argv"][1] = \
            "--service-discovery-namespace=wrong"
        with self.assertRaisesRegex(REN.ManifestError, "process differs"):
            contract(changed)
        changed = json.loads(json.dumps(allowlist))
        # The router is a seeded entry.
        router_entry = next(name for name in changed["workloads"] if name.startswith("c8s-router"))
        changed["workloads"][router_entry]["containers"][0]["args"] = {"policy": "any"}
        with self.assertRaisesRegex(REN.ManifestError, "entry c8s-router.* differs"):
            contract(changed)

    def test_the_example_deployments_hold_no_live_address(self):
        text = "".join(path.read_text() for path in DEPLOYMENTS.iterdir())
        for live in ("api.confidential.ai", "cloudapp.azure.com", "172.173.", "10.45.250.26", "10.43.58.194"):
            self.assertNotIn(live, text)


class ChartArchiveTests(unittest.TestCase):
    def test_the_package_version_is_the_tag_without_v(self):
        self.assertEqual(MAN.chart_version("v0.14.12"), "0.14.12")
        for tag in ("v0.14.12-staging", "0.14.12", "v0.14"):
            with self.subTest(tag=tag), self.assertRaisesRegex(MAN.ManifestError, "vX.Y.Z"):
                MAN.chart_version(tag)
        self.assertEqual(MAN.chart_reference("confidential-inference", "0.14.12"),
                         "ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:0.14.12")

    def test_the_package_is_the_tagged_chart_at_the_release_version_and_reproducible(self):
        first = MAN.package_chart(MAN.CHART, "confidential-inference", "0.14.12")
        self.assertEqual(first, MAN.package_chart(MAN.CHART, "confidential-inference", "0.14.12"))
        self.assertNotEqual(first, MAN.package_chart(MAN.CHART, "confidential-inference", "0.14.13"))
        with tarfile.open(fileobj=io.BytesIO(first)) as tar:
            names = sorted(tar.getnames())
            chart_yaml = yaml.safe_load(tar.extractfile("confidential-inference/Chart.yaml").read())
            self.assertTrue(all(m.mtime == 0 and m.uid == 0 and m.mode == 0o644 for m in tar.getmembers()))
        self.assertEqual(names, sorted(f"confidential-inference/{p.relative_to(MAN.CHART).as_posix()}"
                                       for p in MAN.CHART.rglob("*") if p.is_file()))
        self.assertEqual(chart_yaml["version"], "0.14.12")
        self.assertEqual(chart_yaml["name"], "confidential-inference")

    def test_a_changed_template_changes_the_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary) / "chart"
            shutil.copytree(MAN.CHART, copy)
            before = MAN.package_chart(copy, "confidential-inference", "0.14.12")
            (copy / "templates/gateway.yaml").write_text("changed: true\n")
            self.assertNotEqual(before, MAN.package_chart(copy, "confidential-inference", "0.14.12"))

    def test_helm_reads_the_package(self):
        if shutil.which("helm") is None:
            self.skipTest("helm is not on PATH")
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "confidential-inference-0.14.12.tgz"
            archive.write_bytes(MAN.package_chart(MAN.CHART, "confidential-inference", "0.14.12"))
            shown = subprocess.run(["helm", "show", "chart", str(archive)], capture_output=True, text=True, check=True)
            self.assertEqual(yaml.safe_load(shown.stdout)["version"], "0.14.12")

if __name__ == "__main__":
    unittest.main()
