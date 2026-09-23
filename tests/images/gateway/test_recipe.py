#!/usr/bin/env python3
"""Test the gateway container recipe without the migrated source."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / "images" / "gateway"
DOCKERFILE = (RECIPE / "Dockerfile").read_text(encoding="utf-8")
LOCK = json.loads((RECIPE / "source.lock").read_text(encoding="utf-8"))
DOCKERIGNORE = (RECIPE / "Dockerfile.dockerignore").read_text(encoding="utf-8")
BUILD_SCRIPT = (RECIPE / "build.sh").read_text(encoding="utf-8")

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
        self.assertNotIn(".infisical.json", DOCKERIGNORE)
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

    def test_build_script_requires_a_clean_committed_source(self) -> None:
        self.assertIn("rev-parse --verify 'HEAD^{commit}'", BUILD_SCRIPT)
        self.assertIn("^[0-9a-f]{40}$", BUILD_SCRIPT)
        self.assertIn("status --porcelain --untracked-files=all", BUILD_SCRIPT)
        self.assertIn("SOURCE_REVISION=$source_revision", BUILD_SCRIPT)
        self.assertIn("SOURCE_DATE_EPOCH=$source_date_epoch", BUILD_SCRIPT)
        self.assertIn('"$repo_root"', BUILD_SCRIPT)

    def test_recipe_directory_has_only_public_build_material(self) -> None:
        expected = {
            "Dockerfile",
            "Dockerfile.dockerignore",
            "README.md",
            "build.sh",
            "source.lock",
        }
        actual = {path.name for path in RECIPE.iterdir() if path.is_file()}
        self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
