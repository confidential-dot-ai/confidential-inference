#!/usr/bin/env python3
"""Tests of harden_media.py against the pinned SGLang source.

Downloads only the public pinned source files and never imports SGLang. The
loader tests run the patched functions themselves and need Pillow; they are
skipped without it.
"""
import ast
import base64
import importlib.util
import io
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.request import urlopen

try:
    from PIL import Image
except ImportError:
    Image = None

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("harden_media", ROOT / "images/sglang/harden_media.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
PIN = "a7fd2e1158c389c33077bae67fb797efa8dd09bd"
COMMON = "srt/utils/common.py"
# Loaders that once fetched URLs or opened caller-named files.
LOADERS = {
    COMMON: ("load_image", "get_image_bytes", "_normalize_video_input", "get_video_bytes",
             "load_audio", "download_remote_media", "get_mm_http_session"),
    "srt/multimodal/cache/identity.py": ("_read_media_bytes",),
    "srt/multimodal/processors/mimo_v2.py": ("MiMoProcessor.has_audio_track", "MiMoProcessor.fetch_image"),
    "srt/multimodal/processors/mimo_audio.py": ("MiMoAudioPipeline.preprocess_audio",),
    "srt/multimodal/processors/moss_vl.py": ("MossVLImageProcessor._normalize_video_string",),
    "srt/multimodal/processors/inkling.py": ("_resolve_media_item",),
    "srt/multimodal/inkling/image_processing.py": ("_load_image_bytes",),
    "srt/multimodal/inkling/feature_extraction.py": ("_load_audio_bytes",),
}
FORBIDDEN_CALLS = {"open", "download_remote_media", "common.download_remote_media", "get_mm_http_session",
                   "session.get", "urlopen", "os.path.isfile", "Path.read_bytes"}
# Names lifted from the patched common.py for the loader tests.
LIFTED = ("IMAGE_FORMATS", "_URL_SCHEME", "inline_media_bytes", "get_image_bytes", "_open_allowed_image",
          "_load_image", "_fully_load_pil_image", "load_image", "download_remote_media",
          "_normalize_video_input", "get_video_bytes")


def called_names(node):
    return {ast.unparse(call.func) for call in ast.walk(node) if isinstance(call, ast.Call)}


def lift(source):
    """The LIFTED definitions of a patched common.py, executed with stubs."""
    tree = ast.parse(source)
    body = [node for node in tree.body
            if getattr(node, "name", None) in LIFTED
            or (isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) in LIFTED)]
    namespace = {
        "re": __import__("re"), "pybase64": base64, "BytesIO": io.BytesIO, "Image": Image,
        "Union": __import__("typing").Union, "Optional": __import__("typing").Optional,
        "torch": SimpleNamespace(Tensor=object), "requests": SimpleNamespace(Session=object),
        "GPUImageDecodeMode": bool, "ImageData": type("ImageData", (), {}),
        "VideoData": type("VideoData", (), {}), "is_jpeg_with_cuda": lambda *args: False,
        "_open_any_image": Image.open,
    }
    exec(compile(ast.Module(body=body, type_ignores=[]), COMMON, "exec"), namespace)
    return namespace


def encoded(image_format, **options):
    buffer = io.BytesIO()
    Image.new("RGB", (8, 6), (200, 30, 30)).save(buffer, image_format, **options)
    return buffer.getvalue()


class Canary(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        Canary.hits.append(self.path)
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:1/")
        self.end_headers()

    def log_message(self, *args):
        pass


class Events:
    """Audit events naming a watched path or opening a connection."""

    watched = ()
    seen = []

    @classmethod
    def hook(cls, event, args):
        if event.startswith("socket.") and event != "socket.__new__":
            cls.seen.append(event)
        elif event == "open" and any(path in str(args[0]) for path in cls.watched):
            cls.seen.append(f"open {args[0]}")


sys.addaudithook(Events.hook)


class MediaPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {}
        for path in policy.SOURCE_HASHES:
            url = f"https://raw.githubusercontent.com/sgl-project/sglang/{PIN}/python/sglang/{path}"
            with urlopen(url, timeout=60) as response:
                cls.sources[path] = response.read().decode()
        cls.hardened = {path: policy.harden(path, source) for path, source in cls.sources.items()}

    def test_pinned_source_patches_and_fails_closed_on_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path, source in self.sources.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(source)
            policy.patch(root)
            for path, hardened in self.hardened.items():
                self.assertEqual(hardened, (root / path).read_text(), path)
            with self.assertRaises(ValueError):
                policy.patch(root)

    def test_every_edit_applies_once(self):
        for path, edits in policy.TEXT_EDITS.items():
            for old, new in edits:
                with self.subTest(path=path, old=old[:60]):
                    self.assertEqual(1, self.sources[path].count(old))
                    self.assertIn(new, self.hardened[path])

    def test_loaders_have_no_fetch_or_file_branch(self):
        for path, names in LOADERS.items():
            tree = ast.parse(self.hardened[path])
            for name in names:
                with self.subTest(path=path, loader=name):
                    calls = called_names(policy.definition(tree, name))
                    self.assertFalse(calls & FORBIDDEN_CALLS, sorted(calls & FORBIDDEN_CALLS))
        for path, hardened in self.hardened.items():
            with self.subTest(path=path):
                self.assertNotIn("download_remote_media(", hardened.replace("def download_remote_media(", ""))
                self.assertNotIn("session.get(", hardened)

    def test_video_decoder_takes_bytes_only(self):
        tree = ast.parse(self.hardened["srt/utils/video_decoder.py"])
        init = policy.definition(tree, "VideoDecoderWrapper.__init__")
        guard = init.body[1]
        self.assertIsInstance(guard, ast.If)
        self.assertEqual("not isinstance(source, bytes)", ast.unparse(guard.test))
        self.assertIsInstance(guard.body[0], ast.Raise)

    @unittest.skipIf(Image is None, "needs Pillow")
    def test_inline_images_decode_unchanged(self):
        common = lift(self.hardened[COMMON])
        jpeg = encoded("JPEG")
        self.assertTrue(base64.b64encode(jpeg).startswith(b"/9j/"))
        cases = {
            "png data URL": "data:image/png;base64," + base64.b64encode(encoded("PNG")).decode(),
            "jpeg data URL": "data:image/jpeg;base64," + base64.b64encode(jpeg).decode(),
            "gif data URL": "data:image/gif;base64," + base64.b64encode(encoded("GIF")).decode(),
            "webp data URL": "data:image/webp;base64," + base64.b64encode(encoded("WEBP")).decode(),
            "raw base64 jpeg": base64.b64encode(jpeg).decode(),
            "bytes": encoded("PNG"),
        }
        for label, value in cases.items():
            with self.subTest(label):
                image, size = common["load_image"](value, False)
                self.assertEqual((8, 6), image.size)
                self.assertIsNone(size)

    @unittest.skipIf(Image is None, "needs Pillow")
    def test_urls_and_paths_are_refused_without_io(self):
        common = lift(self.hardened[COMMON])
        server = ThreadingHTTPServer(("127.0.0.1", 0), Canary)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_port}"
        with tempfile.TemporaryDirectory() as directory:
            canary = Path(directory) / "canary.png"
            canary.write_bytes(encoded("PNG"))
            Events.watched, Events.seen, Canary.hits = (str(canary), "canary"), [], []
            inputs = (f"{base}/image.png", f"{base}/redirect", "https://127.0.0.1:1/image.png",
                      f"file://{canary}", str(canary), "canary.png", "ftp://127.0.0.1/image.png",
                      f"video:{canary}")
            for loader in ("load_image", "get_image_bytes", "get_video_bytes", "_normalize_video_input"):
                for value in inputs:
                    with self.subTest(loader=loader, value=value):
                        with self.assertRaises(ValueError):
                            common[loader](value)
            with self.assertRaisesRegex(ValueError, "not supported"):
                common["download_remote_media"](f"{base}/image.png", 5)
            Events.watched = ()
        server.shutdown()
        server.server_close()
        self.assertEqual([], Events.seen)
        self.assertEqual([], Canary.hits)

    @unittest.skipIf(Image is None, "needs Pillow")
    def test_images_outside_the_allowlist_are_refused(self):
        common = lift(self.hardened[COMMON])
        eps = b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 8 6\nshowpage\n%%EOF\n"
        for label, data in {"eps": eps, "bmp": encoded("BMP"), "tiff": encoded("TIFF")}.items():
            with self.subTest(label):
                self.assertIsNotNone(Image.open(io.BytesIO(data)).format)
                with self.assertRaisesRegex(ValueError, "Could not decode image"):
                    common["load_image"]("data:image/x;base64," + base64.b64encode(data).decode(), False)
                with self.assertRaises(OSError):
                    common["_open_allowed_image"](io.BytesIO(data))
                with self.assertRaises(OSError):
                    common["_open_allowed_image"](io.BytesIO(data), formats=[label.upper()])


if __name__ == "__main__":
    unittest.main()
