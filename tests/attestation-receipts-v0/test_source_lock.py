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

    def run_tool(self, commit: str | None = None) -> subprocess.CompletedProcess[str]:
        arguments = [
            "python3",
            str(SCRIPT),
            "--repository",
            str(self.repository),
            "--lock",
            str(self.lock),
        ]
        if commit is not None:
            arguments.extend(["--commit", commit])
        return subprocess.run(arguments, text=True, capture_output=True)

    def add_second_commit(self) -> str:
        """Commit a second c8s source file and pin it as a further `commits`
        list entry, alongside the existing top-level entry."""
        second = self.repository / "second.go"
        second.write_text("package second\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repository), "add", "second.go"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "commit", "-qm", "second"], check=True,
        )
        second_commit = subprocess.run(
            ["git", "-C", str(self.repository), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        second_digest = "sha256:" + hashlib.sha256(b"package second\n").hexdigest()
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["commits"] = [
            {
                "commit": second_commit,
                "nodeImage": "example/node@sha256:" + "3" * 64,
                "c8sOperatorImage": "example/c8s@sha256:" + "4" * 64,
                "requiredVerifierFlags": ["--allowlist"],
                "files": {"second.go": second_digest},
            }
        ]
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        return second_commit

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

    def test_accepts_release_entry_metadata_used_by_the_public_lock(self) -> None:
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["tag"] = "v0.26.5"
        value["capabilities"] = {"allowlistCanonicalize": False}
        value["attestationProtocol"] = "c8s/attest-pq/v1+xwing"
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_unknown_release_entry_metadata(self) -> None:
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["attestationProtocol"] = "unknown"
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attestation protocol is invalid", result.stderr)

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


    def test_each_listed_commit_resolves_to_its_own_entry(self) -> None:
        second_commit = self.add_second_commit()
        result = self.run_tool(commit=self.commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["commit"], self.commit)
        result = self.run_tool(commit=second_commit)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["commit"], second_commit)
        self.assertEqual(payload["nodeImage"], "example/node@sha256:" + "3" * 64)
        self.assertIn("second.go", payload["files"])

    def test_unlisted_commit_fails_closed(self) -> None:
        self.add_second_commit()
        result = self.run_tool(commit="c" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not pinned in the source lock", result.stderr)

    def test_commits_list_rejects_a_duplicate_commit(self) -> None:
        value = json.loads(self.lock.read_text(encoding="utf-8"))
        value["commits"] = [
            {
                "commit": self.commit,
                "nodeImage": "example/node@sha256:" + "3" * 64,
                "c8sOperatorImage": "example/c8s@sha256:" + "4" * 64,
                "requiredVerifierFlags": ["--allowlist"],
                "files": {"proof.go": "sha256:" + "0" * 64},
            }
        ]
        self.lock.write_text(json.dumps(value), encoding="utf-8")
        result = self.run_tool()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("same commit twice", result.stderr)


if __name__ == "__main__":
    unittest.main()
