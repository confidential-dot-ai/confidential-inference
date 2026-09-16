from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/verify-c8s-admission-source.py"


class SourceLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "c8s"
        self.repository.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repository)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.email", "test@example.com"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.name", "Test"],
            check=True,
        )
        source = self.repository / "proof.go"
        source.write_text("package proof\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repository), "add", "proof.go"], check=True)
        subprocess.run(["git", "-C", str(self.repository), "commit", "-qm", "proof"], check=True)
        self.commit = subprocess.run(
            ["git", "-C", str(self.repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        source_digest = "sha256:" + hashlib.sha256(b"package proof\n").hexdigest()
        self.lock = self.root / "lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema": "confidential-inference.c8s-admission-source-lock/v1",
                    "commit": self.commit,
                    "nodeImage": "example/node@sha256:" + "1" * 64,
                    "c8sOperatorImage": "example/c8s@sha256:" + "2" * 64,
                    "requiredVerifierFlags": ["--allowlist"],
                    "candidate": {"status": "staging-only", "commit": "b" * 40},
                    "files": {"proof.go": source_digest},
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_tool(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "python3",
                str(SCRIPT),
                "--repository",
                str(self.repository),
                "--lock",
                str(self.lock),
            ],
            text=True,
            capture_output=True,
        )

    def test_reads_the_pinned_commit_instead_of_the_dirty_tree(self) -> None:
        (self.repository / "proof.go").write_text("dirty\n", encoding="utf-8")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["commit"], self.commit)

    def test_active_commit_can_stand_alone_without_a_candidate(self) -> None:
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        del value["candidate"]
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["candidateSourceStatus"], "not-declared")

    def test_wrong_source_digest_fails_closed(self) -> None:
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["files"]["proof.go"] = "sha256:" + "0" * 64
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source differs", result.stderr)

    def test_candidate_source_checks_require_complete_file_coverage(self) -> None:
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["candidate"]["sourceChecks"] = {
            "status": "pending-final-integration",
            "files": ["proxy.go"],
            "content": {},
        }
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not cover every file", result.stderr)

    def test_release_candidate_checks_source_markers(self) -> None:
        candidate_file = self.repository / "candidate.go"
        candidate_file.write_text("package candidate\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repository), "add", "candidate.go"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "commit", "-qm", "candidate"],
            check=True,
        )
        candidate_commit = subprocess.run(
            ["git", "-C", str(self.repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["candidate"] = {
            "status": "release-ready",
            "commit": candidate_commit,
            "sourceChecks": {
                "status": "verified",
                "files": ["candidate.go"],
                "content": {"candidate.go": ["package candidate"]},
            },
        }
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["candidateSourceStatus"], "verified")


if __name__ == "__main__":
    unittest.main()
