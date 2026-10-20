import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
canonicalize = runpy.run_path(str(ROOT / "images/sglang-router/canonicalize_wheel.py"))["canonicalize"]


class RouterWheelTests(unittest.TestCase):
    def wheel(self, path, names, binary=b"native binary"):
        payloads = {"router/native.so": binary, "router/launch.py": b"print(1)",
                    "router.dist-info/RECORD": b"unchanged record"}
        with zipfile.ZipFile(path, "w") as archive:
            for name in names:
                entry = zipfile.ZipInfo(name, (2026, 10, 9, 13, 29, 6))
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, payloads[name])
        return payloads

    def test_order_changes_do_not_change_canonical_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory)/"a.whl", Path(directory)/"b.whl"
            names = ["router/native.so", "router/launch.py", "router.dist-info/RECORD"]
            expected = self.wheel(a, names)
            self.wheel(b, names[::-1])
            self.assertNotEqual(a.read_bytes(), b.read_bytes())
            canonicalize(a)
            canonicalize(b)
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with zipfile.ZipFile(a) as archive:
                for entry in archive.infolist():
                    self.assertEqual(archive.read(entry), expected[entry.filename])
                    self.assertEqual(entry.external_attr, 0o100644 << 16)
                    self.assertEqual(entry.date_time, (2026, 10, 9, 13, 29, 6))
            before = a.read_bytes()
            canonicalize(a)
            self.assertEqual(a.read_bytes(), before)

    def test_changed_native_binary_still_changes_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = Path(directory)/"a.whl", Path(directory)/"b.whl"
            names = ["router/native.so", "router/launch.py", "router.dist-info/RECORD"]
            self.wheel(a, names)
            self.wheel(b, names, binary=b"different binary")
            canonicalize(a)
            canonicalize(b)
            self.assertNotEqual(hashlib.sha256(a.read_bytes()).digest(), hashlib.sha256(b.read_bytes()).digest())

    def test_duplicate_entries_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            a = Path(directory)/"a.whl"
            with zipfile.ZipFile(a, "w") as archive:
                archive.writestr("duplicate", b"one")
                with self.assertWarns(UserWarning):
                    archive.writestr("duplicate", b"two")
            before = a.read_bytes()
            with self.assertRaisesRegex(ValueError, "duplicate"):
                canonicalize(a)
            self.assertEqual(a.read_bytes(), before)
