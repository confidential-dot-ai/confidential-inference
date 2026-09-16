from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "images/sglang/wait_for_model.py"
REVISION = "9e165c30e2704aec5d9d593cce3eebd58bbef1cb"
REPOSITORY = "deepseek-ai/DeepSeek-V4-Flash-0731"


class ModelMountGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.model = self.base / "model"
        self.mountinfo = self.base / "mountinfo"
        self.mountinfo.write_text("")

    def create_model(self, *, writable: bool = False, revision: str = REVISION) -> dict[str, str]:
        self.model.mkdir()
        files = {
            "config.json": b'{"model_type":"deepseek_v4"}\n',
            "tokenizer_config.json": b'{"tokenizer_class":"DeepseekTokenizer"}\n',
            "model.safetensors.index.json": json.dumps(
                {"weight_map": {"layer.weight": "model-00001-of-00001.safetensors"}},
                sort_keys=True,
            ).encode() + b"\n",
        }
        for name, content in files.items():
            (self.model / name).write_bytes(content)
        (self.model / "model-00001-of-00001.safetensors").write_bytes(b"weights")
        inventory = [
            {
                "content_sha256": hashlib.sha256((self.model / name).read_bytes()).hexdigest(),
                "path": name,
                "size": (self.model / name).stat().st_size,
            }
            for name in sorted(files)
        ]
        manifest = {
            "canonical_local_manifest_sha256": "1" * 64,
            "classification": "verified_local_snapshot_bytes",
            "files": inventory,
            "immutable_ref": f"{REPOSITORY}@{revision}",
            "immutable_revision": revision,
            "repository": REPOSITORY,
            "schema": "confidential-benchmark/local-model-byte-manifest/v1",
            "source_remote_inventory_sha256": "2" * 64,
        }
        manifest_bytes = json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
        (self.model / ".model-lock-local-manifest.json").write_bytes(manifest_bytes)
        files[".model-lock-local-manifest.json"] = manifest_bytes
        for path in self.model.rglob("*"):
            path.chmod(0o555 if path.is_dir() else 0o444)
        self.model.chmod(0o755 if writable else 0o555)
        return {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}

    def set_mount(
        self,
        *,
        read_only: bool = True,
        c8s: bool = True,
        bind_read_only: bool = True,
        filesystem: str = "erofs",
    ) -> None:
        mount_options = "ro" if bind_read_only else "rw"
        super_options = "ro" if read_only else "rw"
        source = "/dev/mapper/c8s-verity-pod-dsv4" if c8s else "/dev/sda"
        self.mountinfo.write_text(
            f"44 33 0:77 / {self.model.resolve()} {mount_options},relatime - {filesystem} {source} {super_options}\n"
        )

    def run_gate(self, digests: dict[str, str], timeout: int = 1) -> subprocess.CompletedProcess[str]:
        command = [
            "python3", str(SCRIPT), "--path", str(self.model),
            "--timeout-seconds", str(timeout), "--poll-seconds", "0.05",
            "--expected-repository", REPOSITORY,
            "--expected-revision", REVISION,
            "--revision-metadata", ".model-lock-local-manifest.json",
            "--mountinfo", str(self.mountinfo),
        ]
        for name in sorted(digests):
            command.extend(["--expected-file", f"{name}={digests[name]}"])
        command.extend(["--", "python3", "-c", "print('server-started')"])
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout + 2)

    def test_verified_mount_starts_the_server_command(self) -> None:
        digests = self.create_model()
        self.set_mount()
        result = self.run_gate(digests)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("server-started\n", result.stdout)
        self.assertIn("model-mount: verified", result.stderr)

    def test_read_only_filesystem_behind_rw_bind_starts_the_server(self) -> None:
        digests = self.create_model()
        self.set_mount(bind_read_only=False)
        result = self.run_gate(digests)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_erofs_with_rw_kernel_flags_starts_the_server(self) -> None:
        digests = self.create_model()
        self.set_mount(read_only=False, bind_read_only=False)
        result = self.run_gate(digests)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_c8s_mapping_behind_a_bind_filesystem_starts_the_server(self) -> None:
        digests = self.create_model()
        self.set_mount(filesystem="ext4")
        result = self.run_gate(digests)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_missing_mount_fails_closed(self) -> None:
        digests = self.create_model()
        result = self.run_gate(digests)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("not a mount point", result.stderr)
        self.assertNotIn("server-started", result.stdout)

    def test_late_mount_starts_before_the_timeout(self) -> None:
        digests: dict[str, str] = {}

        def make_available() -> None:
            time.sleep(0.2)
            digests.update(self.create_model())
            self.set_mount()

        thread = threading.Thread(target=make_available)
        thread.start()
        expected = {
            "config.json": hashlib.sha256(b'{"model_type":"deepseek_v4"}\n').hexdigest(),
            "tokenizer_config.json": hashlib.sha256(b'{"tokenizer_class":"DeepseekTokenizer"}\n').hexdigest(),
            "model.safetensors.index.json": hashlib.sha256(
                json.dumps(
                    {"weight_map": {"layer.weight": "model-00001-of-00001.safetensors"}},
                    sort_keys=True,
                ).encode() + b"\n"
            ).hexdigest(),
        }
        result = self.run_gate(expected, timeout=2)
        thread.join()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_overlay_placeholder_waits_for_c8s_mapping(self) -> None:
        digests = self.create_model()
        self.set_mount(c8s=False, filesystem="overlay", read_only=False, bind_read_only=False)

        def attach_c8s_volume() -> None:
            time.sleep(0.2)
            self.set_mount()

        thread = threading.Thread(target=attach_c8s_volume)
        thread.start()
        result = self.run_gate(digests, timeout=2)
        thread.join()
        self.assertEqual(0, result.returncode, result.stderr)

    def test_c8s_mount_over_the_placeholder_starts_the_server(self) -> None:
        digests = self.create_model()
        target = self.model.resolve()
        self.mountinfo.write_text(
            f"44 33 0:77 / {target} ro,relatime - overlay overlay rw\n"
            f"45 44 252:3 / {target} ro,nosuid,nodev,noexec - erofs "
            "/dev/mapper/c8s-verity-pod-dsv4 ro\n"
        )
        result = self.run_gate(digests)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_wrong_revision_fails_closed(self) -> None:
        digests = self.create_model(revision="0" * 40)
        self.set_mount()
        result = self.run_gate(digests)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("revision manifest", result.stderr)

    def test_writable_mount_fails_closed(self) -> None:
        digests = self.create_model(writable=True)
        self.set_mount(read_only=False)
        result = self.run_gate(digests)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("permits writes", result.stderr)

    def test_non_c8s_mount_fails_closed(self) -> None:
        digests = self.create_model()
        self.set_mount(c8s=False)
        result = self.run_gate(digests)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("c8s dm-verity mapping is not attached", result.stderr)

    def test_corrupt_metadata_fails_closed(self) -> None:
        digests = self.create_model()
        self.set_mount()
        (self.model / "config.json").chmod(0o644)
        (self.model / "config.json").write_text('{"corrupt":true}\n')
        (self.model / "config.json").chmod(0o444)
        result = self.run_gate(digests)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("wrong digest: config.json", result.stderr)

    def test_missing_weight_shard_fails_closed(self) -> None:
        digests = self.create_model()
        self.set_mount()
        shard = self.model / "model-00001-of-00001.safetensors"
        self.model.chmod(0o755)
        shard.unlink()
        self.model.chmod(0o555)
        result = self.run_gate(digests)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("missing shard", result.stderr)


if __name__ == "__main__":
    unittest.main()
