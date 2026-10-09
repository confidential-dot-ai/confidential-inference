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

import functools
import importlib.util
import json
import shutil
import subprocess
import sys
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


def build_staging(evidence: dict, base: dict | None = None, tag: str = "v0.14.2-staging",
                  c8s: Path | None = None) -> dict[str, bytes]:
    """Build the staging release with crane and the signature check replaced.

    Without `c8s`, the fixture allowlist replaces the c8s CLI. With `c8s`, the
    build generates the allowlist with that c8s CLI binary.
    """
    generated = STAGING_ALLOWLIST.read_bytes().removesuffix(b"\n")
    generate = MAN.ALLOWLIST_GENERATOR["generate"] if c8s else lambda *_args, **_kwargs: generated
    with tempfile.TemporaryDirectory() as temporary:
        evidence_path = Path(temporary) / "publication.json"
        evidence_path.write_text(json.dumps(evidence))
        download_dir = Path(temporary) / "base"
        if base is not None:
            download_dir.mkdir()
            (download_dir / "release-bundle.json").write_text(json.dumps(base))
            (download_dir / "release-bundle.sigstore.json").write_text("{}")
        with mock.patch.object(MAN, "verify_image_source_boundary"), \
                mock.patch.object(MAN, "changed_paths", return_value=[]), \
                mock.patch.object(MAN.release_signature, "verify_release_signature"), \
                mock.patch.object(MAN.shutil, "which", return_value="/usr/bin/cosign"), \
                mock.patch.dict(MAN.ALLOWLIST_GENERATOR, {
                    "generate": generate,
                    "image_config": REPOSITORY_CONFIGS.__getitem__,
                }):
            return MAN.build(
                tag,
                ROOT / "helm/confidential-inference",
                ROOT / "contracts/c8s-admission-source-lock.json",
                "d" * 40,
                evidence_path,
                download_dir,
                c8s or Path("c8s"),
                None,
            )


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

    def test_host_path_pins_source_and_mode(self):
        container = {"name": "app", "image": IMAGE, "volumeMounts": [{"name": "proc", "mountPath": "/host/proc", "readOnly": True}]}
        obj = controller(container=container, volumes=[{"name": "proc", "hostPath": {"path": "/proc"}}])
        self.assertEqual(GEN.container_mounts(obj, container, None),
                         [{"destination": "/host/proc", "kind": "host", "source": "/proc", "readOnly": True}])


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

    def test_floor_entry_name_mirrors_c8s(self):
        name, entry = GEN.floor_entry(CORE)
        self.assertEqual(name, "c8s-operator-" + "b" * 12)
        self.assertEqual(entry["containers"][0]["env"], {"policy": "any"})


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

    def test_the_committed_file_accepts_exactly_four_findings(self):
        accepted = GEN.read_accepted_findings(ROOT / "release/accepted-lint-findings.json")
        self.assertEqual(len(accepted), 4)
        self.assertEqual({key[4] for key in accepted}, {"/usr/bin/nvidia-smi", "/usr/bin/nvidia-persistenced"})

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
            self.assertEqual(staging_allowlist(Path("/tmp/c8s")), STAGING_ALLOWLIST.read_bytes())
        self.assertEqual(calls, [Path("/tmp/c8s")])

    def test_staging_manifest_uses_the_staging_profile(self):
        files = build_staging(publication(published_release_images()))
        manifest = json.loads(files["release-bundle.json"])
        self.assertEqual(manifest["release"], {"name": "v0.14.2-staging", "environment": "staging"})
        self.assertEqual(manifest["allowlist"], {
            "path": "release/staging/allowlist.json",
            "sha256": MAN.sha256(STAGING_ALLOWLIST.read_bytes()),
        })
        self.assertEqual(files["allowlist.json"], STAGING_ALLOWLIST.read_bytes())
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
            (directory / "release-bundle.json").write_text(json.dumps(base))
            (directory / "release-bundle.sigstore.json").write_text("{}")
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
            policy = allowlist["workloads"][name]["containers"][0]
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

    def test_staging_policy_uses_its_exact_render_and_allowlist_namespace(self):
        spec = MAN.read_spec(STAGING)
        policy = MAN.read_allowlist_policy(STAGING.policy)
        core = spec["c8s"]["coreImages"]
        documents = rendered(STAGING)
        allowlist = json.loads(STAGING_ALLOWLIST.read_text())
        configs = {**json.loads(PROFILES.IMAGE_CONFIG.read_text()), **REPOSITORY_CONFIGS}
        MAN.require_allowlist_contract(allowlist, policy, core, documents, configs)
        router = next(item for item in documents if item.get("kind") == "Deployment"
                      and item.get("metadata", {}).get("name") == "sglang-router")
        args = router["spec"]["template"]["spec"]["containers"][0]["args"]
        self.assertIn("--service-discovery-namespace=confidential-inference-staging", args)
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"].pop("inference-worker-1")
        with self.assertRaisesRegex(MAN.ManifestError, "entries differ"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs)
        changed = json.loads(json.dumps(allowlist))
        changed["workloads"]["sglang-router"]["containers"][0]["args"]["argv"][1] = \
            "--service-discovery-namespace=wrong"
        with self.assertRaisesRegex(MAN.ManifestError, "process differs"):
            MAN.require_allowlist_contract(changed, policy, core, documents, configs)

    def test_each_node_manifest_belongs_to_the_layer_that_pins_c8s(self):
        for profile in PROFILES.load():
            with self.subTest(profile=profile.name):
                if (profile.directory / "node-manifest.json").exists():
                    self.assertEqual(PROFILES.node_manifest(profile), profile.directory / "node-manifest.json")
                self.assertFalse((profile.directory / "inputs/image-config.json").exists()
                                 and profile.directory / "inputs/image-config.json" != PROFILES.IMAGE_CONFIG)

    def test_the_source_lock_pins_the_spec_commit(self):
        lock = json.loads((ROOT / "contracts/c8s-admission-source-lock.json").read_text())
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
        schema = json.loads((ROOT / "contracts/release-manifest.schema.json").read_text())
        properties = set(schema["properties"])
        for forbidden in ("meshCa", "operatorPublicKeySha256", "operatorKeySetSha256", "target"):
            self.assertNotIn(forbidden, properties)
        self.assertFalse(schema["additionalProperties"])
        jsonschema.Draft202012Validator.check_schema(schema)


class ChartArchiveTests(unittest.TestCase):
    def test_the_package_version_is_the_tag_without_v_and_suffix(self):
        self.assertEqual(MAN.chart_version("v0.14.12-staging", STAGING), "0.14.12")
        self.assertEqual(MAN.chart_version("v0.14.12", PRODUCTION), "0.14.12")
        with self.assertRaisesRegex(MAN.ManifestError, "profile"):
            MAN.chart_version("v0.14.12", STAGING)
        self.assertEqual(MAN.chart_reference("confidential-inference", "0.14.12"),
                         "ghcr.io/confidential-dot-ai/confidential-inference/charts/confidential-inference:0.14.12")

    def test_the_package_holds_the_tagged_chart_with_the_release_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = MAN.package_chart(MAN.CHART, "0.14.12", Path(temporary))
            self.assertEqual(archive.name, "confidential-inference-0.14.12.tgz")
            MAN.verify_archive_content(archive, MAN.CHART, "0.14.12")
            with self.assertRaisesRegex(MAN.ManifestError, "version"):
                MAN.verify_archive_content(archive, MAN.CHART, "0.14.13")

    def test_a_changed_template_fails_the_content_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            copy = Path(temporary) / "chart"
            shutil.copytree(MAN.CHART, copy)
            archive = MAN.package_chart(copy, "0.14.12", Path(temporary))
            (copy / "templates/gateway.yaml").write_text("changed: true\n")
            with self.assertRaisesRegex(MAN.ManifestError, "templates/gateway.yaml"):
                MAN.verify_archive_content(archive, copy, "0.14.12")
            (copy / "templates/extra.yaml").write_text("extra: true\n")
            with self.assertRaisesRegex(MAN.ManifestError, "templates/extra.yaml"):
                MAN.verify_archive_content(archive, copy, "0.14.12")


if __name__ == "__main__":
    unittest.main()
