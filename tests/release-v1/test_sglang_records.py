"""The published engine record is consumed without changing its bytes or publisher."""

import copy
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import confidential_sglang_release as CSR  # noqa: E402

NAME = "images-0123456789ab"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def published_record():
    return {
        "schema": CSR.RECORD_SCHEMA, "repository": "https://github.com/" + CSR.REPOSITORY,
        "sourceCommit": COMMIT, "sourceDateEpoch": 1795169221,
        "run": {"repository": "example/builds", "id": 17, "attempt": 2,
                "url": "https://github.com/example/builds/actions/runs/17/attempts/2",
                "workflow": "example/builds/.github/workflows/images.yml@refs/heads/main"},
        "images": [
            {"name": name, "image": CSR.IMAGE_PREFIX + name, "digest": "sha256:" + char * 64,
             "reference": CSR.IMAGE_PREFIX + name + "@sha256:" + char * 64,
             "tag": "sha-" + COMMIT, "builds": ["sha256:" + char * 64] * 2}
            for name, char in (("engine", "e"), ("router", "f"))
        ],
    }


class PublishedRecordTests(unittest.TestCase):
    def test_download_pin_and_manifest_bind_the_exact_published_bytes(self):
        data = (json.dumps(published_record(), indent=2) + "\n").encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = root / "spec.yaml"
            spec.write_text(f"confidentialSglang:\n  record: {CSR.PLACEHOLDER}\n")
            calls = []

            def run(command, **kwargs):
                calls.append(command)
                directory = Path(command[command.index("--dir") + 1])
                (directory / (NAME + ".json")).write_bytes(data)
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            CSR.pin(NAME, spec, root / "inputs", fetch=lambda name, directory: CSR.download(name, directory, run))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][calls[0].index("--pattern") + 1], NAME + ".json")
            self.assertEqual(calls[0][calls[0].index("--repo") + 1], CSR.REPOSITORY)
            self.assertEqual((root / "inputs" / (NAME + ".json")).read_bytes(), data)
            self.assertIn("  record: " + NAME, spec.read_text())
            pin = CSR.release_pin({"record": NAME}, root / "inputs")
            self.assertEqual(pin["recordSha256"], "sha256:" + hashlib.sha256(data).hexdigest())
            self.assertEqual(pin["recordAsset"], NAME + ".json")
            self.assertEqual(pin["repository"], CSR.REPOSITORY)
            self.assertEqual(pin["runId"], 17)
            self.assertEqual(pin["sourceCommit"], COMMIT)
            self.assertEqual(pin["images"]["engine"]["reference"], published_record()["images"][0]["reference"])
            self.assertEqual(pin["images"]["router"]["buildDigests"], ["sha256:" + "f" * 64] * 2)
            schema = json.loads((ROOT / "api/release-manifest-v2.schema.json").read_text())
            jsonschema.Draft202012Validator({**schema["properties"]["confidentialSglang"],
                                            "$defs": schema["$defs"]}).validate(pin)

    def test_invalid_publisher_metadata_or_image_binding_is_rejected(self):
        cases = [
            (("schema",), "other"), (("repository",), "https://github.com/other/repo"),
            (("sourceCommit",), "f" * 40), (("sourceDateEpoch",), True), (("sourceDateEpoch",), 0),
            (("run",), []), (("run", "repository"), "../escape"), (("run", "id"), True),
            (("run", "id"), 0), (("run", "attempt"), True), (("run", "attempt"), -1),
            (("run", "url"), "https://example.test/run"), (("run", "workflow"), "other/repo/workflow"),
            (("images",), {}), (("images",), [published_record()["images"][0]] * 2),
            (("images",), list(reversed(published_record()["images"]))),
            (("images", 0, "image"), "ghcr.io/other/engine"),
            (("images", 0, "reference"), "ghcr.io/example/engine@sha256:" + "e" * 64),
            (("images", 0, "tag"), "sha-" + "f" * 40), (("images", 0, "digest"), "sha256:invalid"),
            (("images", 0, "builds"), ["sha256:" + "e" * 64, "sha256:" + "f" * 64]),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                record = published_record()
                target = record
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.assertRaises(CSR.RecordError):
                    CSR.validate_record(record, NAME)
        for path in ((), ("run",), ("images", 0)):
            record = published_record()
            target = record
            for part in path:
                target = target[part]
            target["extra"] = True
            with self.subTest(extra=path), self.assertRaises(CSR.RecordError):
                CSR.validate_record(record, NAME)

    def test_contract_selector_uses_the_same_validated_record(self):
        path = ROOT / "tests/images/engine-contract/pinned_engine.py"
        spec = importlib.util.spec_from_file_location("published_engine_pin", path)
        selector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(selector)
        with tempfile.TemporaryDirectory() as temporary:
            inputs = Path(temporary)
            record = published_record()
            path = inputs / (NAME + ".json")
            path.write_text(json.dumps(record))
            self.assertEqual(selector.from_record({"confidentialSglang": {"record": NAME}}, inputs),
                             record["images"][0]["reference"])
            invalid = copy.deepcopy(record)
            invalid["images"][0]["builds"][1] = "sha256:" + "f" * 64
            path.write_text(json.dumps(invalid))
            with self.assertRaises(CSR.RecordError):
                selector.from_record({"confidentialSglang": {"record": NAME}}, inputs)


if __name__ == "__main__":
    unittest.main()
