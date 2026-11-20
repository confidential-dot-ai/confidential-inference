#!/usr/bin/env python3
"""Test the gateway container recipe without the migrated source."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "gateway"
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")
LOCK = json.loads((RECIPE / "source.lock").read_text(encoding="utf-8"))
DOCKERIGNORE = (RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")

BUILD_IMAGE = "docker.io/library/rust"
BUILD_DIGEST = "sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55"
RUNTIME_IMAGE = "gcr.io/distroless/cc-debian12"
RUNTIME_DIGEST = "sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f"


def instructions() -> list[str]:
    return [
        line.strip()
        for line in DOCKERFILE.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class GatewayImageRecipeTests(unittest.TestCase):
    def test_each_base_image_uses_the_locked_digest(self) -> None:
        from_lines = [line for line in instructions() if line.upper().startswith("FROM ")]
        self.assertEqual(
            [
                f"FROM {BUILD_IMAGE}@{BUILD_DIGEST} AS build",
                f"FROM {RUNTIME_IMAGE}@{RUNTIME_DIGEST}",
            ],
            from_lines,
        )
        self.assertEqual(BUILD_DIGEST, LOCK["build"]["digest"])
        self.assertEqual(RUNTIME_DIGEST, LOCK["runtime"]["digest"])

    def test_build_uses_only_the_future_gateway_package(self) -> None:
        self.assertIn("COPY Cargo.toml Cargo.lock rust-toolchain.toml ./", DOCKERFILE)
        self.assertIn("COPY services/gateway/Cargo.toml services/gateway/Cargo.toml", DOCKERFILE)
        self.assertIn("COPY services/gateway/src services/gateway/src", DOCKERFILE)
        self.assertIn(
            "COPY services/maintenance-gateway/Cargo.toml services/maintenance-gateway/Cargo.toml",
            DOCKERFILE,
        )
        self.assertIn(
            "COPY services/maintenance-gateway/src services/maintenance-gateway/src",
            DOCKERFILE,
        )
        self.assertIn(
            "cargo build --locked --release --package confidential-gateway --bin confidential-gateway",
            DOCKERFILE,
        )
        # The build must copy the in-repository sources. It must never name an
        # absolute path in a maintainer home directory.
        self.assertIsNone(
            re.search(r"(?:/home|/Users)/[A-Za-z0-9._-]+/", DOCKERFILE),
            "the Dockerfile names an absolute home directory path",
        )

    def test_build_context_excludes_every_unlisted_file(self) -> None:
        self.assertEqual(
            [
                "**",
                "!Cargo.toml",
                "!Cargo.lock",
                "!rust-toolchain.toml",
                "!services/",
                "!services/gateway/",
                "!services/gateway/Cargo.toml",
                "!services/gateway/src/",
                "!services/gateway/src/**",
                "!services/maintenance-gateway/",
                "!services/maintenance-gateway/Cargo.toml",
                "!services/maintenance-gateway/src/",
                "!services/maintenance-gateway/src/**",
            ],
            DOCKERIGNORE.splitlines(),
        )
        self.assertNotIn(".kube", DOCKERIGNORE)

    def test_runtime_has_one_kubernetes_entrypoint(self) -> None:
        self.assertIn('ENTRYPOINT ["/usr/local/bin/confidential-gateway"]', DOCKERFILE)
        self.assertNotRegex(DOCKERFILE, re.compile(r"^\s*CMD\b", re.MULTILINE | re.IGNORECASE))
        self.assertEqual(["/usr/local/bin/confidential-gateway"], LOCK["runtime"]["entrypoint"])

    def test_runtime_uses_a_numeric_non_root_identity(self) -> None:
        self.assertIn("USER 65532:65532", DOCKERFILE)
        self.assertEqual(65532, LOCK["runtime"]["uid"])
        self.assertEqual(65532, LOCK["runtime"]["gid"])
        self.assertNotRegex(DOCKERFILE, re.compile(r"^\s*USER\s+(?:0|root)(?::|\s|$)", re.MULTILINE))

    def test_runtime_uses_only_high_ports(self) -> None:
        self.assertIn("EXPOSE 9443 9090", DOCKERFILE)
        exposed = re.search(r"^EXPOSE\s+(.+)$", DOCKERFILE, re.MULTILINE)
        self.assertIsNotNone(exposed)
        assert exposed is not None
        self.assertTrue(all(int(port) >= 1024 for port in exposed.group(1).split()))

    def test_recipe_has_no_host_or_cloud_runtime(self) -> None:
        forbidden = re.compile(
            r"\b(systemd|systemctl|sshd?|openssh|tailscale|tailnet|azure|key[ -]?vault)\b",
            re.IGNORECASE,
        )
        self.assertIsNone(forbidden.search(DOCKERFILE))
        self.assertNotRegex(
            DOCKERFILE,
            re.compile(r"\b(?:apt|apt-get|apk|dnf|yum|curl|wget)\b", re.IGNORECASE),
        )

    def test_labels_bind_the_public_source_and_build_revision(self) -> None:
        required = {
            'LABEL org.opencontainers.image.source="https://github.com/confidential-dot-ai/confidential-inference"',
            'LABEL org.opencontainers.image.revision="${SOURCE_REVISION}"',
            'LABEL org.opencontainers.image.licenses="Apache-2.0"',
            f'LABEL org.opencontainers.image.base.digest="{RUNTIME_DIGEST}"',
            f'LABEL ai.confidential.build.rust.digest="{BUILD_DIGEST}"',
        }
        self.assertTrue(required.issubset(set(instructions())))
        self.assertIn('case "${SOURCE_REVISION}" in *[!0-9a-f]*', DOCKERFILE)
        self.assertIn('test "${#SOURCE_REVISION}" -eq 40', DOCKERFILE)
        self.assertIn('case "${SOURCE_DATE_EPOCH}" in *[!0-9]*', DOCKERFILE)
        self.assertIn('LABEL org.opencontainers.image.version="sha-${SOURCE_REVISION}"', DOCKERFILE)
        self.assertIn('LABEL ai.confidential.build.source-date-epoch="${SOURCE_DATE_EPOCH}"', DOCKERFILE)
        self.assertNotIn("org.opencontainers.image.created", DOCKERFILE)


class GatewayBuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.environment = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull,
                            "GIT_CONFIG_NOSYSTEM": "1"}
        for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "services/gateway/Cargo.toml"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        recipe = self.root / "images/gateway"
        recipe.mkdir(parents=True)
        shutil.copyfile(RECIPE / "build.sh", recipe / "build.sh")
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                 "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        commands = self.root / "commands"
        commands.mkdir()
        self.calls = self.root / "docker.json"
        docker = commands / "docker"
        docker.write_text(
            "#!/usr/bin/env python3\nimport json,os,sys\n"
            "with open(os.environ['TEST_DOCKER_LOG'], 'w') as log: json.dump(sys.argv[1:], log)\n")
        docker.chmod(0o755)
        self.environment.update(PATH=f"{commands}:{os.environ['PATH']}", TEST_DOCKER_LOG=str(self.calls))

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.root), *arguments], env=self.environment,
                              capture_output=True, text=True, check=True).stdout.strip()

    def build(self):
        return subprocess.run(["bash", str(self.root / "images/gateway/build.sh"), "--load"],
                              env=self.environment, capture_output=True, text=True, timeout=10)

    def test_clean_source_passes_its_identity_and_build_options_to_docker(self):
        revision = self.git("rev-parse", "HEAD")
        epoch = self.git("show", "-s", "--format=%ct", "HEAD")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = json.loads(self.calls.read_text())
        self.assertEqual(arguments, [
            "buildx", "build", "--file", str(self.root / "images/gateway/Dockerfile"),
            "--build-arg", f"SOURCE_REVISION={revision}", "--build-arg", f"SOURCE_DATE_EPOCH={epoch}",
            "--load", str(self.root),
        ])

    def test_changed_or_untracked_build_inputs_never_reach_docker(self):
        for name in ("services/gateway/Cargo.toml", "services/gateway/untracked.rs"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_bytes() if path.exists() else None
                path.write_text("uncommitted input\n")
                result = self.build()
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertIn("uncommitted changes", result.stderr)
                self.assertFalse(self.calls.exists())
                if original is None:
                    path.unlink()
                else:
                    path.write_bytes(original)

    def test_missing_build_input_never_reaches_docker(self):
        (self.root / "Cargo.lock").unlink()
        result = self.build()
        self.assertEqual(result.returncode, 66, result.stderr)
        self.assertIn("Cargo.lock", result.stderr)
        self.assertFalse(self.calls.exists())


if __name__ == "__main__":
    unittest.main()
