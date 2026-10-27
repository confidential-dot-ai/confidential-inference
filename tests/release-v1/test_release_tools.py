"""Unit tests for the v0.14.0 release tools in scripts/.

These tests use no network, no cluster, and no c8s binary. They cover the
parts of the tools that decide the allowlist and the manifest content.

The repository holds no digest of an image that it builds, so the tests
render the chart with fixtures/release-values.yaml: the digests of the
v0.14.0 images. fixtures/staging-allowlist.json is the staging allowlist that
the c8s CLI of the staging c8s pin generates from those digests;
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
NODE = load("fetch_node_manifest", "scripts/fetch-node-manifest.py")
PROFILES = sys.modules["release_profiles"]
PRODUCTION = PROFILES.for_directory(ROOT / "release")
STAGING = PROFILES.for_directory(ROOT / "release/staging")
FIXTURES = ROOT / "tests/release-v1/fixtures"
OVERLAY = FIXTURES / "release-values.yaml"
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


@functools.cache
def rendered(profile) -> list[dict]:
    """The chart rendered with the profile values and its policy settings. Do not change it."""
    return MAN.render_chart(MAN.CHART, profile, MAN.read_allowlist_policy(profile.policy)["chart"], OVERLAY)


def publication(images: dict[str, str], *, commit: str = "b" * 40, base_ref: str = "v0.13.28-rc.2",
                base_commit: str = "c" * 40) -> dict:
    return {
        "schema": "confidential.ai/image-publication-manifest/v2",
        "source": {"repository": REPOSITORY, "commit": commit, "baseRef": base_ref, "baseRefCommit": base_commit},
        "images": [{"name": name, "digest": digest} for name, digest in sorted(images.items())],
    }


def published_release_images() -> dict[str, str]:
    """The fixture digests by repository, as the image publication names them."""
    return dict(image.split("@", 1) for image in RELEASE_IMAGES.values())


def staging_seed(tag: str, commit: str, platform: str) -> dict:
    """The staging pin's C8s seed asset, as the staging fixture mirrors it (its
    entries that no policy names), so the tests need no network."""
    profile = next(profile for profile in PROFILES.load() if profile.name == "staging")
    c8s = PROFILES.read_spec(profile)["c8s"]
    if (tag, commit, platform) != (c8s["release"], c8s["sourceCommit"], "tdx"):
        raise GEN.c8s_release.ReleaseError(f"no test seed for c8s {tag} {platform}")
    names = {item["name"] for item in json.loads(profile.policy.read_text())["workloads"]}
    workloads = json.loads(STAGING_ALLOWLIST.read_text())["workloads"]
    return {"schema": "c8s.allowlist/v1", "workloads": {name: entry for name, entry in workloads.items() if name not in names}}


def setUpModule():
    patch = mock.patch.object(GEN.c8s_release, "allowlist_seed", side_effect=staging_seed)
    patch.start()
    unittest.addModuleCleanup(patch.stop)


def write_release(directory: Path, manifest: dict) -> None:
    """Put a release manifest and an empty Sigstore bundle where the build downloads them."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "release-bundle.json").write_text(json.dumps(manifest))
    (directory / "release-bundle.sigstore.json").write_text("{}")


def build_release(tag: str, evidence: dict, download_dir: Path | None, generate, *patches,
                  c8s: Path | None = None) -> dict[str, bytes]:
    """Build a release with crane and the signature check replaced, plus `patches`."""
    with tempfile.TemporaryDirectory() as temporary, contextlib.ExitStack() as stack:
        evidence_path = Path(temporary) / "publication.json"
        evidence_path.write_text(json.dumps(evidence))
        for patch in patches:
            stack.enter_context(patch)
        stack.enter_context(mock.patch.object(MAN, "verify_image_source_boundary"))
        stack.enter_context(mock.patch.object(MAN, "changed_paths", return_value=[]))
        stack.enter_context(mock.patch.object(MAN.release_signature, "verify_release_signature"))
        # A real cosign stays: generating with a c8s CLI verifies the C8s seed asset.
        which = MAN.shutil.which
        stack.enter_context(mock.patch.object(MAN.shutil, "which", side_effect=lambda name: which(name) or "/usr/bin/cosign"))
        stack.enter_context(mock.patch.dict(MAN.ALLOWLIST_GENERATOR, {
            "generate": generate, "image_config": REPOSITORY_CONFIGS.__getitem__,
        }))
        return MAN.build(
            tag,
            ROOT / "helm/confidential-inference",
            ROOT / "release/inputs/c8s-source-lock.json",
            "d" * 40,
            evidence_path,
            download_dir or Path(temporary) / "downloads",
            c8s or Path("c8s"),
            None,
        )


def build_staging(evidence: dict, base: dict | None = None, tag: str = "v0.14.2-staging",
                  c8s: Path | None = None) -> dict[str, bytes]:
    """Build the staging release. Without `c8s`, the fixture allowlist replaces the c8s CLI."""
    generated = STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n")
    generate = MAN.ALLOWLIST_GENERATOR["generate"] if c8s else lambda *_args, **_kwargs: generated
    with tempfile.TemporaryDirectory() as temporary:
        download_dir = Path(temporary) / "base"
        if base is not None:
            write_release(download_dir, base)
        return build_release(tag, evidence, download_dir, generate, c8s=c8s)


def build_production(evidence: dict, download_dir: Path, tag: str = "v0.14.2") -> dict[str, bytes]:
    """Build the production release with the fixture allowlist.

    The fixture allowlist is the staging one. The production values pin another
    c8s operator image, so the stub adds its digest; the allowlist contract and
    the model files are not what the production tests check.
    """
    allowlist = json.loads(STAGING_ALLOWLIST.read_text())
    operator = PROFILES.read_values(PRODUCTION)["images"]["c8sOperator"].rsplit("@", 1)[1]
    allowlist["workloads"]["production-operator"] = {"containers": [{"digest": operator}]}
    # Staging runs no kube-state-metrics (it needs the Kubernetes API).
    metrics = PROFILES.read_values(PRODUCTION)["images"]["kubeStateMetrics"].rsplit("@", 1)[1]
    allowlist["workloads"]["production-kube-state-metrics"] = {"containers": [{"digest": metrics}]}
    generated = json.dumps(allowlist).encode()
    return build_release(tag, evidence, download_dir, lambda *_args, **_kwargs: generated,
                         mock.patch.object(MAN, "require_allowlist_contract"),
                         mock.patch.object(MAN, "require_model_files"))


def staging_allowlist(c8s: Path) -> bytes:
    """Return the fixture allowlist as the c8s CLI binary `c8s` generates it.

    scripts/bump-c8s.py writes it to fixtures/staging-allowlist.json when the
    staging profile moves to another c8s release.
    """
    return build_staging(publication(published_release_images()), c8s=c8s)["allowlist.json"]


def rendered_workers(profile) -> list[dict]:
    return [item for item in rendered(profile) if item.get("kind") == "StatefulSet"
            and item.get("metadata", {}).get("name", "").startswith("inference-worker-")]

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


class TransitionCompositionTests(unittest.TestCase):
    def test_transition_base_uses_the_final_component_not_its_old_rollback_image(self):
        repository = 'ghcr.io/confidential-dot-ai/confidential-inference/gateway'
        base = {'source': {'commit': 'a'*40}, 'transition': {},
                'images': {'gateway': repository+'@sha256:'+'b'*64,
                           'transitionInput0': repository+'@sha256:'+'c'*64}}
        evidence = {'source': {'baseRef': 'v0.14.18-transition', 'baseRefCommit': 'a'*40,
                              'commit': 'd'*40}, 'images': []}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(MAN, 'signed_release', return_value=base), \
             mock.patch.object(MAN, 'changed_paths', return_value=[]):
            result = MAN.base_release_images(evidence, Path(folder))
        self.assertEqual(result[repository], 'sha256:'+'b'*64)

    def test_transition_manifest_requires_its_signed_input_binding(self):
        manifest = json.loads(build_staging(publication(published_release_images()))['release-bundle.json'])
        manifest['release']['name'] = 'v0.14.18-transition-staging'
        with self.assertRaises(MAN.ManifestError):
            MAN.validate_schema(manifest)
        ref = lambda tag: {'name': tag, 'bundleSha256': 'sha256:'+'a'*64,
                           'allowlistSha256': 'sha256:'+'b'*64}
        manifest['transition'] = {'fromRelease': ref('v0.14.17-staging'),
                                  'finalRelease': ref('v0.14.18-staging'), 'helperWorkloads': []}
        MAN.validate_schema(manifest)
        manifest['release']['name'] = 'v0.14.18-staging'
        with self.assertRaises(MAN.ManifestError):
            MAN.validate_schema(manifest)

    def setUp(self):
        self.image = 'example/app@sha256:' + 'a' * 64
        self.entry = {'initContainers': [], 'containers': [{
            'image': self.image, 'digest': 'sha256:' + 'a' * 64,
            'command': {'policy': 'exact', 'argv': ['/app']},
            'args': {'policy': 'deny'}, 'env': {'policy': 'exact', 'values': {}},
            'mounts': {'policy': 'deny'}}]}

    def policy(self, *names):
        return {'schema': 'c8s.allowlist/v1', 'workloads': {name: copy.deepcopy(self.entry) for name in names}}

    def compose(self, helpers=None, new=None):
        return MAN.compose_transition_policy(self.policy('old'), new or self.policy('final'),
                                             helpers or {}, {self.image})

    def test_old_final_and_helpers_are_all_preserved(self):
        result = self.compose({'test-client': self.entry})
        self.assertEqual(set(result['workloads']), {'old', 'final', 'test-client'})

    def test_changed_shared_identity_cannot_be_silently_overwritten(self):
        new = self.policy('old')
        new['workloads']['old']['containers'][0]['args'] = {'policy': 'exact', 'argv': ['--changed']}
        with self.assertRaisesRegex(MAN.ManifestError, 'conflicting definitions'):
            self.compose(new=new)

    def test_unapproved_helper_image_is_rejected(self):
        entry = copy.deepcopy(self.entry)
        entry['containers'][0]['image'] = 'another/app@sha256:' + 'b' * 64
        with self.assertRaisesRegex(MAN.ManifestError, 'no approved release image'):
            self.compose({'helper': entry})

    def test_mismatched_digest_is_rejected(self):
        entry = copy.deepcopy(self.entry)
        entry['containers'][0]['digest'] = 'sha256:' + 'b' * 64
        with self.assertRaisesRegex(MAN.ManifestError, 'image and digest differ'):
            self.compose({'helper': entry})

    def test_unrestricted_new_helper_is_rejected(self):
        entry = copy.deepcopy(self.entry)
        entry['containers'][0]['mounts'] = {'policy': 'any'}
        with self.assertRaisesRegex(MAN.ManifestError, 'must have exact'):
            self.compose({'helper': entry})

    def test_transition_tags_select_the_existing_environment_profiles(self):
        self.assertEqual(PROFILES.for_tag('v0.14.18-transition').name, 'production')
        self.assertEqual(PROFILES.for_tag('v0.14.18-transition-staging').name, 'staging')
        for tag in ['v0.14.18-staging-transition', 'v0.14.18-transition-transition']:
            with self.assertRaises(PROFILES.ProfileError):
                PROFILES.for_tag(tag)



    def test_helper_cannot_reuse_an_application_identity(self):
        with self.assertRaisesRegex(MAN.ManifestError, 'separate workload identities'):
            self.compose({'final': self.entry})

    def test_helper_image_key_uses_verified_image_without_a_manual_digest(self):
        entry = copy.deepcopy(self.entry)
        container = entry['containers'][0]
        container.pop('image'); container.pop('digest'); container['imageKey'] = 'rolloutClient'
        resolved = MAN.resolve_transition_helpers({'helper': entry}, {'rolloutClient': self.image})
        self.assertEqual(resolved['helper'], self.entry)
        container['digest'] = 'sha256:' + 'a' * 64
        with self.assertRaisesRegex(MAN.ManifestError, 'manual digest'):
            MAN.resolve_transition_helpers({'helper': entry}, {'rolloutClient': self.image})

    def test_helper_hosts_use_final_workload_ids_without_changing_the_program(self):
        entry = copy.deepcopy(self.entry)
        entry['containers'][0]['env']['values'] = {'HOSTS': 'gateway,${ROUTER_WORKLOAD_ID}'}
        entry['containers'][0]['args'] = {'policy': 'exact', 'argv': ['literal ${ROUTER_WORKLOAD_ID} in program']}
        resolved = MAN.resolve_transition_helpers({'helper': entry}, {}, 'v0.14.18-transition')
        self.assertEqual(resolved['helper']['containers'][0]['env']['values']['HOSTS'], 'gateway,router-v0-14-18')
        self.assertEqual(resolved['helper']['containers'][0]['args'], entry['containers'][0]['args'])
        with self.assertRaisesRegex(MAN.ManifestError, 'unresolved environment marker'):
            MAN.resolve_transition_helpers({'helper': entry}, {})

    def test_transition_requires_the_exact_final_replacement_policy(self):
        old, final = self.policy('old'), self.policy('final')
        def manifest(policy):
            return {'images': {'gateway': self.image}, 'source': {'commit': 'a'*40},
                    'c8s': {'sourceCommit': 'b'*40}, 'nodeImage': {'reference': 'node'},
                    'allowlist': {'sha256': MAN.sha256(json.dumps(policy).encode())}}
        spec = {'transition': {'fromRelease': 'v0.14.17', 'helpers': {}}}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(MAN, 'signed_allowlist',
                side_effect=[(manifest(old), old, 'sha256:'+'c'*64),
                             (manifest(final), final, 'sha256:'+'d'*64)]):
            with self.assertRaisesRegex(MAN.ManifestError, 'differ from the signed final policy'):
                MAN.transition_policy('v0.14.18-transition', spec, 'a'*40,
                    json.dumps(self.policy('different')).encode(), {'gateway': self.image},
                    None, Path(folder), Path('c8s'), PRODUCTION)


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
        policy = MAN.read_allowlist_policy(STAGING.policy)
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
        MAN.require_allowlist_contract(allowlist, selected, [], [pod], {})
        changed = copy.deepcopy(allowlist)
        changed["workloads"]["gateway-update-agent"]["containers"][0]["args"]["argv"][-1] = "unreviewed code"
        with self.assertRaisesRegex(MAN.ManifestError, "process differs"):
            MAN.require_allowlist_contract(changed, selected, [], [pod], {})


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
        MAN.require_allowlist_contract({"workloads": seed}, policy, [CORE], [], configs, "v0.47.0", core_seed=seed)
        with self.assertRaisesRegex(MAN.ManifestError, "entries differ"):
            MAN.require_allowlist_contract({"workloads": {**seed, "extra": shape}}, policy, [CORE], [], configs,
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
                with self.assertRaisesRegex(GEN.GenerationError, "differ from the profile"):
                    GEN.core_seed(spec)

    def test_without_a_record_the_core_seed_is_the_release_asset_of_the_node_image_platform(self):
        seed = {"schema": "c8s.allowlist/v1", "workloads": {"c8s-router-" + "0" * 12: {}}}
        spec = {"release": "v0.74.0", "sourceCommit": "a" * 40, "coreImages": [CORE],
                "nodeImage": {"tag": "rke2-tdx-cdi-v0.74.0"}}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(GEN, "ROOT", Path(directory)), \
                mock.patch.object(GEN.c8s_release, "allowlist_seed", return_value=seed) as asset:
            self.assertEqual(GEN.core_seed(spec), seed["workloads"])
            asset.assert_called_once_with("v0.74.0", "a" * 40, "tdx")
            asset.side_effect = GEN.c8s_release.ReleaseError("does not verify")
            with self.assertRaisesRegex(GEN.GenerationError, "does not verify"):
                GEN.core_seed(spec)
            with self.assertRaisesRegex(GEN.GenerationError, "names no platform"):
                GEN.core_seed({**spec, "nodeImage": {"tag": "custom"}})


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
        MAN.require_allowlist_contract(allowlist, policy, [], [document], {}, "v0.44.6-beta.1")
        for change in (lambda e: e["containers"].append(copy.deepcopy(e["containers"][0])),
                       lambda e: e["containers"][0]["args"]["argv"].append("--unreviewed")):
            changed = copy.deepcopy(allowlist)
            change(changed["workloads"]["worker"])
            with self.assertRaisesRegex(MAN.ManifestError, "process differs"):
                MAN.require_allowlist_contract(changed, policy, [], [document], {}, "v0.44.6-beta.1")

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


class ManifestTests(unittest.TestCase):
    def test_signed_beta_version_is_a_valid_release_input(self):
        spec = MAN.read_spec(PRODUCTION)
        for version in ('v0.37.0-beta.1', 'v0.37.0'):
            MAN.validate_spec({**spec, 'c8s': {**spec['c8s'], 'release': version}})
        for version in ('v0.37.0-beta.0', 'v0.37.0-beta.01', 'v0.37.0-rc.1'):
            with self.assertRaisesRegex(MAN.ManifestError, 'c8s.release'):
                MAN.validate_spec({**spec, 'c8s': {**spec['c8s'], 'release': version}})

    def test_the_committed_spec_is_valid(self):
        MAN.read_spec(PRODUCTION)
        MAN.read_spec(STAGING)

    def test_only_staging_may_pin_a_c8s_beta(self):
        for profile, allowed in ((STAGING, True), (PRODUCTION, False)):
            spec = copy.deepcopy(PROFILES.read_spec(profile))
            spec["c8s"]["release"] = "v0.73.0-beta.1"
            spec["c8s"].pop("baseRelease", None)
            with self.subTest(profile=profile.name), mock.patch.object(PROFILES, "read_spec", return_value=spec):
                if allowed:
                    MAN.read_spec(profile)
                else:
                    with self.assertRaisesRegex(MAN.ManifestError, "stable c8s release"):
                        MAN.read_spec(profile)

    def test_the_spec_names_no_version_because_the_tag_is_the_version(self):
        spec = MAN.read_spec(PRODUCTION)
        with self.assertRaisesRegex(MAN.ManifestError, "the tag is the version"):
            MAN.validate_spec({**spec, "version": "v0.14.0"})
        for profile in PROFILES.load():
            self.assertNotIn("releaseId", PROFILES.read_values(profile)["attestationReceipts"])

    def test_the_tag_names_the_release_and_selects_the_profile(self):
        files = build_staging(publication(published_release_images()), tag="v0.14.9-staging")
        manifest = json.loads(files["release-bundle.json"])
        self.assertEqual(manifest["release"], {"name": "v0.14.9-staging", "environment": "staging"})
        self.assertEqual(yaml.safe_load(files["release-values.yaml"])["attestationReceipts"],
                         {"releaseId": "v0.14.9-staging"})
        for tag in ("v0.14.9-rc.1", "v0.14.9-staging.1", "staging"):
            with self.subTest(tag=tag), self.assertRaisesRegex(MAN.ManifestError, "no release profile"):
                build_staging(publication(published_release_images()), tag=tag)

    def test_image_source_boundary_allows_only_later_non_image_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            gateway = repo / "images/gateway/Dockerfile"
            gateway.parent.mkdir(parents=True)
            gateway.write_text("FROM scratch\n")
            release_values = repo / "release/values.yaml"
            release_values.parent.mkdir(parents=True)
            release_values.write_text("version: first\n")
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "image source"], cwd=repo, check=True)
            image_source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()

            release_values.write_text("version: pinned\n")
            subprocess.run(["git", "commit", "-qam", "pin release"], cwd=repo, check=True)
            release_source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
            MAN.verify_image_source_boundary(image_source, release_source, repo)

            gateway.write_text("FROM scratch\nLABEL changed=yes\n")
            subprocess.run(["git", "commit", "-qam", "change image"], cwd=repo, check=True)
            changed_source = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repo, text=True
            ).strip()
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

    def test_the_staging_fixture_is_the_allowlist_that_the_given_c8s_cli_generates(self):
        calls = []

        def generate(_profile, c8s, *_args, **_kwargs):
            calls.append(c8s)
            return STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n")

        with mock.patch.dict(MAN.ALLOWLIST_GENERATOR, {"generate": generate}):
            self.assertEqual(staging_allowlist(Path("/tmp/c8s")), STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n"))
        self.assertEqual(calls, [Path("/tmp/c8s")])

    def test_staging_manifest_uses_the_staging_profile(self):
        files = build_staging(publication(published_release_images()))
        manifest = json.loads(files["release-bundle.json"])
        self.assertEqual(manifest["release"], {"name": "v0.14.2-staging", "environment": "staging"})
        self.assertEqual(manifest["allowlist"], {
            "path": "release/staging/allowlist.json",
            "sha256": MAN.sha256(STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n")),
        })
        self.assertEqual(files["allowlist.json"], STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n"))
        self.assertFalse(files["allowlist.json"].endswith(b"\n"))
        self.assertEqual(manifest["releaseValues"], {
            "path": "release/staging/release-values.yaml",
            "sha256": MAN.sha256(files["release-values.yaml"]),
        })
        self.assertEqual(manifest["source"]["commit"], "d" * 40)
        self.assertEqual(manifest["imagePublication"]["sourceCommit"], "b" * 40)
        self.assertEqual(yaml.safe_load(files["release-values.yaml"]), {
            "images": RELEASE_IMAGES,
            "attestationReceipts": {"releaseId": "v0.14.2-staging"},
        })
        for key, image in RELEASE_IMAGES.items():
            self.assertEqual(manifest["images"][key], image)

    def test_the_staging_manifest_binds_the_package_and_the_profile_values(self):
        files = build_staging(publication(published_release_images()))
        manifest = json.loads(files["release-bundle.json"])
        archive = files["confidential-inference-0.14.2.tgz"]
        self.assertEqual(manifest["chart"]["archiveSha256"], MAN.sha256(archive))
        self.assertEqual(manifest["chart"]["reference"],
                         "ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:0.14.2")
        self.assertEqual(manifest["chart"]["version"], yaml.safe_load((MAN.CHART / "Chart.yaml").read_text())["version"])
        self.assertEqual(manifest["profileValues"], [
            {"path": "release/values.yaml", "sha256": MAN.sha256((ROOT / "release/values.yaml").read_bytes()),
             "asset": "profile-values-release-values.yaml"},
            {"path": "release/staging/values.yaml",
             "sha256": MAN.sha256((ROOT / "release/staging/values.yaml").read_bytes()),
             "asset": "profile-values-release-staging-values.yaml"},
        ])

    def test_the_release_files_carry_the_profile_values_under_their_asset_names(self):
        files = build_staging(publication(published_release_images()))
        self.assertEqual(files["profile-values-release-values.yaml"], (ROOT / "release/values.yaml").read_bytes())
        self.assertEqual(files["profile-values-release-staging-values.yaml"],
                         (ROOT / "release/staging/values.yaml").read_bytes())

    def test_a_production_release_binds_the_staging_package(self):
        staging = json.loads(build_staging(publication(published_release_images()))["release-bundle.json"])
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(MAN.release_signature, "verify_release_signature"), \
                mock.patch.object(MAN.shutil, "which", return_value="/usr/bin/cosign"):
            directory = Path(temporary)
            write_release(directory / "staging-release", staging)
            binding = MAN.staging_chart_binding("v0.14.2", "d" * 40, staging["chart"]["sha256"], directory)
            self.assertEqual(binding, {"archiveSha256": staging["chart"]["archiveSha256"],
                                       "reference": staging["chart"]["reference"]})
            for bad, message in ((("v0.14.2", "e" * 40, staging["chart"]["sha256"]), "commit"),
                                 (("v0.14.2", "d" * 40, "sha256:" + "0" * 64), "chart tree"),
                                 (("v0.14.3", "d" * 40, staging["chart"]["sha256"]), "different release")):
                with self.subTest(message=message), self.assertRaisesRegex(MAN.ManifestError, message):
                    MAN.staging_chart_binding(*bad, directory)
            legacy = {**staging, "chart": {k: v for k, v in staging["chart"].items()
                                           if k not in ("archiveSha256", "reference")}}
            write_release(directory / "staging-release", legacy)
            with self.assertRaisesRegex(MAN.ManifestError, "no chart package"):
                MAN.staging_chart_binding("v0.14.2", "d" * 40, staging["chart"]["sha256"], directory)

    def test_a_production_build_binds_the_staging_package_and_writes_none(self):
        staging_files = build_staging(publication(published_release_images()))
        staging = json.loads(staging_files["release-bundle.json"])
        staging["release"]["name"] = "v0.14.2-staging"
        with tempfile.TemporaryDirectory() as temporary:
            download = Path(temporary) / "downloads"
            write_release(download / "staging-release", staging)
            files = build_production(publication(published_release_images()), download)
        manifest = json.loads(files["release-bundle.json"])
        self.assertEqual(manifest["release"], {"name": "v0.14.2", "environment": "production"})
        self.assertEqual(manifest["chart"]["archiveSha256"], staging["chart"]["archiveSha256"])
        self.assertEqual(manifest["chart"]["reference"], staging["chart"]["reference"])
        self.assertEqual([entry["path"] for entry in manifest["profileValues"]], ["release/values.yaml"])
        self.assertEqual([name for name in files if name.endswith(".tgz")], [])

    def test_a_production_build_without_the_staging_release_says_so(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(MAN, "fetch", side_effect=MAN.ManifestError("cannot download x: 404")):
            with self.assertRaisesRegex(MAN.ManifestError, "v0.14.2-staging, the staging release"):
                build_production(publication(published_release_images()), Path(temporary) / "downloads")

    def test_an_unchanged_image_keeps_the_digest_of_the_signed_base_release(self):
        sglang = "ghcr.io/confidential-dot-ai/confidential-inference/sglang"
        base = json.loads(build_staging(publication(published_release_images()))["release-bundle.json"])
        base["release"]["name"] = "v0.14.1-staging"
        base["source"]["commit"] = "c" * 40
        evidence = publication({sglang: published_release_images()[sglang]}, base_ref="v0.14.1-staging")
        manifest = json.loads(build_staging(evidence, base)["release-bundle.json"])
        self.assertEqual(manifest["images"]["gateway"], RELEASE_IMAGES["gateway"])
        self.assertEqual(manifest["imagePublication"]["images"], {sglang: published_release_images()[sglang]})

    def test_the_base_release_must_match_the_publication(self):
        base = json.loads(build_staging(publication(published_release_images()))["release-bundle.json"])
        base["release"]["name"] = "v0.14.1-staging"
        base["source"]["commit"] = "c" * 40
        evidence = publication({}, base_ref="v0.14.1-staging")
        for value, message in (
            ({**base, "release": {**base["release"], "name": "v0.14.0-staging"}}, "different release"),
            ({**base, "source": {**base["source"], "commit": "e" * 40}}, "base commit"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(MAN.ManifestError, message):
                self.base_images(evidence, value)
        # A release built before releaseValues existed is still a valid base.
        legacy = {key: value for key, value in base.items() if key != "releaseValues"}
        self.assertTrue(self.base_images(evidence, legacy))

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
        base = json.loads(build_staging(publication(published_release_images()))["release-bundle.json"])
        base["release"]["name"] = "v0.14.1-staging"
        base["source"]["commit"] = "c" * 40
        evidence = publication({}, base_ref="v0.14.1-staging")
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

    def test_release_values_take_repository_digests_only_from_evidence(self):
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        values = {"images": {"gateway": gateway, "other": "docker.io/library/busybox@sha256:" + "1" * 64}}
        evidence = publication({gateway: "sha256:" + "2" * 64})
        self.assertEqual(MAN.release_images(values, evidence, {}), {"gateway": f"{gateway}@sha256:{'2' * 64}"})
        self.assertEqual(MAN.release_images(values, publication({}), {gateway: "sha256:" + "3" * 64}),
                         {"gateway": f"{gateway}@sha256:{'3' * 64}"})
        with self.assertRaisesRegex(MAN.ManifestError, "neither"):
            MAN.release_images(values, publication({}), {})
        pinned = {"images": {"gateway": f"{gateway}@sha256:{'4' * 64}"}}
        with self.assertRaisesRegex(MAN.ManifestError, "pins a digest"):
            MAN.release_images(pinned, evidence, {})

    def test_the_repository_holds_no_digest_of_a_repository_image(self):
        for profile in PROFILES.load():
            for key, value in PROFILES.read_values(profile).get("images", {}).items():
                if value.startswith(PROFILES.REPOSITORY_IMAGES):
                    with self.subTest(profile=profile.name, key=key):
                        self.assertNotIn("@", value)
            self.assertFalse(profile.allowlist.exists())
        configs = json.loads(PROFILES.IMAGE_CONFIG.read_text())
        self.assertFalse([image for image in configs if image.startswith(PROFILES.REPOSITORY_IMAGES)])

    @unittest.skip("TEST b200int-20261027a: the test layer runs one Qwen3-1.7B GPU worker, not the stock 2 simulators")
    def test_staging_workers_verify_the_model_before_the_simulator(self):
        workers = rendered_workers(STAGING)
        self.assertEqual(len(workers), 2)
        for worker in workers:
            pod = worker["spec"]["template"]
            container = pod["spec"]["containers"][0]
            self.assertEqual(container["command"], ["/usr/local/bin/wait-for-model"])
            self.assertIn("python3", container["args"])
            self.assertIn("sglang_simulator.simulation.sglang.launch_server", container["args"])
            self.assertIn("confidential.ai/c8s-volumes", pod["metadata"]["annotations"])
            self.assertEqual(container["resources"]["requests"]["memory"], "16Gi")

        allowlist = json.loads(STAGING_ALLOWLIST.read_text())
        zero_digest = "sha256:" + "0" * 64
        for name in ("inference-worker-0", "inference-worker-1"):
            guarded = [item for item in allowlist["workloads"][name]["containers"]
                       if item["command"].get("argv") == ["/usr/local/bin/wait-for-model"]]
            self.assertEqual(len(guarded), 1)
            policy = guarded[0]
            self.assertEqual(policy["command"]["argv"], ["/usr/local/bin/wait-for-model"])
            self.assertIn("sglang_simulator.simulation.sglang.launch_server", policy["args"]["argv"])
        self.assertNotIn(zero_digest, STAGING_ALLOWLIST.read_text())

    def test_manifest_refuses_model_values_that_differ_from_the_spec(self):
        spec = MAN.read_spec(STAGING)
        values = PROFILES.read_values(STAGING)
        MAN.require_model_agreement(spec, values)
        cases = [
            ("name", "different/model", "repository"),
            ("revision", "a" * 40, "revision"),
        ]
        for field, value, message in cases:
            changed = json.loads(json.dumps(values))
            changed["inference"]["model"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(MAN.ManifestError, message):
                MAN.require_model_agreement(spec, changed)

    def test_manifest_refuses_a_rendered_byte_manifest_that_differs_from_the_spec(self):
        spec = MAN.read_spec(STAGING)
        MAN.require_model_files(spec, rendered(STAGING))
        changed = json.loads(json.dumps(rendered(STAGING)))
        for worker in changed:
            if worker.get("kind") == "StatefulSet" and worker["metadata"]["name"].startswith("inference-worker-"):
                container = worker["spec"]["template"]["spec"]["containers"][0]
                container["args"] = [arg.replace(spec["model"]["byteManifestSha256"], "0" * 64)
                                     for arg in container["args"]]
        with self.assertRaisesRegex(MAN.ManifestError, "byte manifest"):
            MAN.require_model_files(spec, changed)

    @staticmethod
    def expected_file_args(profile) -> list[list[str]]:
        return [[arg.removeprefix("--expected-file=")
                 for arg in worker["spec"]["template"]["spec"]["containers"][0]["args"]
                 if arg.startswith("--expected-file=")]
                for worker in rendered_workers(profile)]

    def test_production_workers_check_the_expected_files_map(self):
        verification = PROFILES.read_values(PRODUCTION)["inference"]["model"]["mountVerification"]
        expected = [f"{name}={digest}" for name, digest in sorted(verification["expectedFiles"].items())]
        for arguments in self.expected_file_args(PRODUCTION):
            self.assertEqual(arguments, expected)

    def test_staging_workers_check_only_the_staging_model_files(self):
        verification = PROFILES.read_values(STAGING)["inference"]["model"]["mountVerification"]
        expected = sorted(f"{item['path']}={item['sha256']}" for item in verification["expectedFileList"])
        for arguments in self.expected_file_args(STAGING):
            self.assertEqual(arguments, expected)

    def test_manifest_refuses_publication_evidence_for_an_unrendered_digest(self):
        gateway = "ghcr.io/confidential-dot-ai/confidential-inference/gateway"
        with self.assertRaisesRegex(MAN.ManifestError, "differs from the rendered release"):
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

    @unittest.skip("TEST b200int-20261027a: the test layer runs one Qwen3-1.7B GPU worker, not the stock 2 simulators")
    def test_staging_policy_uses_its_exact_render_and_allowlist_namespace(self):
        spec = MAN.read_spec(STAGING)
        policy = MAN.read_allowlist_policy(STAGING.policy)
        core = spec["c8s"]["coreImages"]
        documents = rendered(STAGING)
        allowlist = json.loads(STAGING_ALLOWLIST.read_text())
        configs = {**json.loads(PROFILES.IMAGE_CONFIG.read_text()), **REPOSITORY_CONFIGS}
        # Use the real CDS process ordering that publication generates.
        allowlist = json.loads(GEN.canonicalize(allowlist, None))
        MAN.require_allowlist_contract(allowlist, policy, core, documents, configs,
                                      GEN.feature_release(spec["c8s"]), GEN.core_seed(spec["c8s"]))
        router = next(item for item in documents if item.get("kind") == "Deployment"
                      and item.get("metadata", {}).get("name") == "sglang-router")
        args = router["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertEqual(args[:3], ["--worker-urls", "http://inference-worker-0-0.inference-workers:30000",
                                    "http://inference-worker-1-0.inference-workers:30000"])
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"].pop("inference-worker-1")
        with self.assertRaisesRegex(MAN.ManifestError, "entries differ"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs,
                                          GEN.feature_release(spec["c8s"]), GEN.core_seed(spec["c8s"]))
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"]["sglang-router"]["containers"][0]["args"]["argv"][1] = \
            "--service-discovery-namespace=wrong"
        with self.assertRaisesRegex(MAN.ManifestError, "process differs"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs,
                                          GEN.feature_release(spec["c8s"]), GEN.core_seed(spec["c8s"]))

        changed = json.loads(json.dumps(allowlist))
        # The router is a seeded entry.
        router_entry = next(name for name in changed["workloads"] if name.startswith("c8s-router"))
        changed["workloads"][router_entry]["containers"][0]["args"] = {"policy": "any"}
        with self.assertRaisesRegex(MAN.ManifestError, "entry c8s-router.* differs"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs,
                                          GEN.feature_release(spec["c8s"]), GEN.core_seed(spec["c8s"]))

    def test_each_node_manifest_belongs_to_the_layer_that_pins_c8s(self):
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                if (profile.directory / "node-manifest.json").exists():
                    self.assertEqual(PROFILES.node_manifest(profile), profile.directory / "node-manifest.json")
                self.assertFalse((profile.directory / "inputs/image-config.json").exists()
                                 and profile.directory / "inputs/image-config.json" != PROFILES.IMAGE_CONFIG)

    def test_the_source_lock_pins_the_spec_commit(self):
        lock = json.loads((ROOT / "release/inputs/c8s-source-lock.json").read_text())
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                spec = MAN.read_spec(profile)
                entry = MAN.source_lock_entry(lock, spec["c8s"]["sourceCommit"])
                self.assertEqual(entry["tag"], spec["c8s"]["release"])
                self.assertEqual(
                    entry["nodeImage"],
                    spec["c8s"]["nodeImage"]["reference"]
                    + "@"
                    + spec["c8s"]["nodeImage"]["digest"],
                )

    def test_the_node_manifest_matches_the_pinned_artifact_layer(self):
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                data = PROFILES.node_manifest(profile).read_bytes()
                pinned = MAN.read_spec(profile)["c8s"]["nodeManifestArtifact"]["manifestJson"]
                self.assertEqual(MAN.sha256(data), pinned)
                NODE.check_measurements(json.loads(data))

    def test_the_schema_refuses_deployment_values(self):
        schema = json.loads((ROOT / "api/release-manifest.schema.json").read_text())
        properties = set(schema["properties"])
        for forbidden in ("meshCa", "operatorPublicKeySha256", "operatorKeySetSha256", "target"):
            self.assertNotIn(forbidden, properties)
        self.assertFalse(schema["additionalProperties"])
        jsonschema.Draft202012Validator.check_schema(schema)

    def test_a_signed_manifest_with_the_old_lock_path_still_validates(self):
        # The published v0.15.15 manifest, which names the lock at contracts/.
        signed = json.loads((FIXTURES / "v0.15.15-release-manifest.json").read_text())
        self.assertEqual(signed["sourceLock"]["path"], "contracts/c8s-admission-source-lock.json")
        MAN.release_signature.validate_release_schema(signed)
        moved = copy.deepcopy(signed)
        moved["sourceLock"]["path"] = MAN.SOURCE_LOCK.relative_to(ROOT).as_posix()
        MAN.release_signature.validate_release_schema(moved)

    def test_a_dev_c8s_build_is_for_staging_only(self):
        schema = json.loads((ROOT / "api/release-manifest.schema.json").read_text())
        dev = "v0.72.1-0.20261023005616-90bd65abd955"
        jsonschema.validate(dev, schema["properties"]["c8s"]["properties"]["release"])
        rules = {"allOf": [rule for rule in schema["allOf"] if "environment" in json.dumps(rule["if"])]}
        jsonschema.validate({"release": {"environment": "staging"}, "c8s": {"release": dev}}, rules)
        jsonschema.validate({"release": {"environment": "production"}, "c8s": {"release": "v0.72.0"}}, rules)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"release": {"environment": "production"}, "c8s": {"release": dev}}, rules)


class ChartArchiveTests(unittest.TestCase):
    def test_the_package_version_is_the_tag_without_v_and_suffix(self):
        self.assertEqual(MAN.chart_version("v0.14.12-staging", STAGING), "0.14.12")
        self.assertEqual(MAN.chart_version("v0.14.12", PRODUCTION), "0.14.12")
        with self.assertRaisesRegex(MAN.ManifestError, "profile"):
            MAN.chart_version("v0.14.12", STAGING)
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
