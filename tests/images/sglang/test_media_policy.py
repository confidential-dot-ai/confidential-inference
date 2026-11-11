#!/usr/bin/env python3
"""Tests of harden_media.py against the pinned SGLang source.

Downloads only the public pinned source files and never imports SGLang. The
loader tests run the patched functions themselves; only image decoding needs
Pillow and is skipped without it.
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
    "srt/multimodal/processors/bailing_mm.py": ("BailingMMMultimodalProcessor._request_url",),
}
# Every FFmpeg-backed decoder entry point and the container check it must call.
FFMPEG_ENTRIES = {
    COMMON: (("load_audio", "inline_media_container"),),
    "srt/utils/video_decoder.py": (("VideoDecoderWrapper.__init__", "inline_media_container"),),
    "srt/multimodal/audio_from_video.py": (("decode_audio_container", "inline_media_container"),),
    "srt/multimodal/processors/mimo_v2.py": (("MiMoProcessor.has_audio_track", "inline_media_container"),),
    "srt/multimodal/processors/mimo_audio.py": (
        ("MiMoAudioPipeline.preprocess_audio", "common.inline_media_container"),),
    "srt/multimodal/processors/moss_vl.py": (
        ("MossVLImageProcessor._normalize_video_string", "inline_media_container"),),
    "srt/multimodal/processors/dots_note_omni_video_core/preprocess.py": (
        ("_make_video_decoder", "inline_media_container"), ("extract_audio_wav", "inline_media_container")),
    "srt/multimodal/processors/bailing_mm.py": (
        ("BailingMMMultimodalProcessor._request_url", "decode"),
        ("BailingMMMultimodalProcessor._processor_fetch_mm_input", "self._request_url")),
}
FORBIDDEN_CALLS = {"open", "download_remote_media", "common.download_remote_media", "get_mm_http_session",
                   "session.get", "urlopen", "os.path.isfile", "Path.read_bytes"}
# Names lifted from the patched common.py for the loader tests.
LIFTED = ("IMAGE_FORMATS", "_URL_SCHEME", "inline_media_bytes", "get_image_bytes", "_open_allowed_image",
          "_load_image", "_fully_load_pil_image", "load_image", "download_remote_media",
          "_normalize_video_input", "get_video_bytes", "_MEDIA_CONTAINER", "_MEDIA_MANIFEST",
          "inline_media_container")
NO_PILLOW = SimpleNamespace(Image=type("Image", (), {}), open=None)


def called_names(node):
    return {ast.unparse(call.func) for call in ast.walk(node) if isinstance(call, ast.Call)}


def lift(source):
    """The LIFTED definitions of a patched common.py, executed with stubs."""
    tree = ast.parse(source)
    body = [node for node in tree.body
            if getattr(node, "name", None) in LIFTED
            or (isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) in LIFTED)]
    namespace = {
        "re": __import__("re"), "pybase64": base64, "BytesIO": io.BytesIO, "Image": Image or NO_PILLOW,
        "Union": __import__("typing").Union, "Optional": __import__("typing").Optional,
        "torch": SimpleNamespace(Tensor=object), "requests": SimpleNamespace(Session=object),
        "GPUImageDecodeMode": bool, "ImageData": type("ImageData", (), {}),
        "VideoData": type("VideoData", (), {}), "is_jpeg_with_cuda": lambda *args: False,
        "_open_any_image": (Image or NO_PILLOW).open,
    }
    exec(compile(ast.Module(body=body, type_ignores=[]), COMMON, "exec"), namespace)
    return namespace


def lift_method(source, qualname, namespace):
    """One method of a patched module, executed as a plain function in namespace."""
    node = policy.definition(ast.parse(source), qualname)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), qualname, "exec"), namespace)
    return namespace[node.name]


def data_url(data, mime="application/octet-stream"):
    return f"data:{mime};base64," + base64.b64encode(data).decode()


MPD = (b'<?xml version="1.0"?><MPD xmlns="urn:mpeg:dash:schema:mpd:2011" '
       b'profiles="urn:mpeg:dash:profile:isoff-on-demand:2011"><BaseURL>http://127.0.0.1:1/a.mp4</BaseURL></MPD>')
# Headers of containers the worker accepts for audio and video.
CONTAINERS = {
    "wav": b"RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00",
    "avi": b"RIFF\x24\x00\x00\x00AVI LIST",
    "mp4": b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00",
    "webm": b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81\x01",
    "flac": b"fLaC\x00\x00\x00\x22",
    "ogg": b"OggS\x00\x02\x00\x00",
    "mp3 id3": b"ID3\x04\x00\x00\x00\x00\x00\x00",
    "mp3 frame": b"\xff\xfb\x90\x64\x00\x00",
    "aac adts": b"\xff\xf1\x50\x80\x00\x1f",
    "amr": b"#!AMR\n\x3c",
}
# Inputs that make FFmpeg select a demuxer that opens nested URLs or files.
MANIFESTS = {
    "dash": MPD,
    "dash after wav header": b"RIFFAAAAWAVE" + MPD,
    "dash after mp4 header": CONTAINERS["mp4"] + MPD.lower(),
    "hls after id3": CONTAINERS["mp3 id3"] + b"#EXTM3U\n#EXTINF:1,\nhttp://127.0.0.1:1/a.ts\n",
    "ffconcat after id3": CONTAINERS["mp3 id3"] + b"ffconcat version 1.0\nfile /etc/hostname\n",
    "sdp after ogg": CONTAINERS["ogg"] + b"\nv=0\nc=IN IP4 127.0.0.1\nm=audio 9 RTP/AVP 0\n",
    "imf": CONTAINERS["webm"] + b'<CompositionPlaylist xmlns="http://www.smpte-ra.org/schemas/2067-3/2016">',
}
OTHER_FORMATS = {
    "png": b"\x89PNG\r\n\x1a\n",
    "text": b"hello",
    "empty": b"",
    "riff without wave": b"RIFF\x24\x00\x00\x00WEBPVP8 ",
}


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
        guard = next(node for node in init.body if isinstance(node, ast.If))
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

    def test_urls_and_paths_are_refused_without_io(self):
        common = lift(self.hardened[COMMON])
        server = ThreadingHTTPServer(("127.0.0.1", 0), Canary)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_port}"
        with tempfile.TemporaryDirectory() as directory:
            canary = Path(directory) / "canary.png"
            canary.write_bytes(CONTAINERS["mp4"])
            Events.watched, Events.seen, Canary.hits = (str(canary), "canary"), [], []
            inputs = (f"{base}/image.png", f"{base}/redirect", "https://127.0.0.1:1/image.png",
                      f"file://{canary}", str(canary), "canary.png", "ftp://127.0.0.1/image.png",
                      f"video:{canary}")
            for loader in ("load_image", "get_image_bytes", "get_video_bytes", "_normalize_video_input",
                           "inline_media_container"):
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

    def test_audio_and_video_accept_only_binary_containers(self):
        common = lift(self.hardened[COMMON])
        check = common["inline_media_container"]
        for label, data in CONTAINERS.items():
            with self.subTest(accepted=label):
                self.assertEqual(data, check(data))
                self.assertEqual(data, check(data_url(data, "audio/wav")))
                self.assertEqual(data, check(base64.b64encode(data).decode()))
        for label, data in {**MANIFESTS, **OTHER_FORMATS}.items():
            for value in (data, data_url(data, "video/mp4"), base64.b64encode(data).decode()):
                with self.subTest(refused=label, kind=type(value).__name__):
                    with self.assertRaises(ValueError):
                        check(value)

    def test_ffmpeg_entries_check_the_container(self):
        for path, entries in FFMPEG_ENTRIES.items():
            tree = ast.parse(self.hardened[path])
            for name, check in entries:
                with self.subTest(path=path, entry=name):
                    self.assertIn(check, called_names(policy.definition(tree, name)))
        self.assertIn('self._request_url(item, inline_media_container)',
                      self.hardened["srt/multimodal/processors/bailing_mm.py"])
        moss = ast.parse(self.hardened["srt/multimodal/processors/moss_vl.py"])
        self.assertNotIn("suffix", ast.unparse(policy.definition(moss, "MossVLImageProcessor._normalize_video_string")))

    def test_bailing_passes_only_data_urls(self):
        common = lift(self.hardened[COMMON])
        namespace = {"ImageData": SimpleNamespace, "VideoData": type("VideoData", (), {}),
                     "inline_media_bytes": common["inline_media_bytes"]}
        request_url = lift_method(self.hardened["srt/multimodal/processors/bailing_mm.py"],
                                  "BailingMMMultimodalProcessor._request_url", namespace)
        mp4 = data_url(CONTAINERS["mp4"], "video/mp4")
        self.assertEqual(mp4, request_url({"url": mp4}))
        self.assertEqual(mp4, request_url(mp4, common["inline_media_container"]))
        refused = ("http://127.0.0.1:1/a.png", "file:///etc/hostname", "/etc/hostname",
                   base64.b64encode(CONTAINERS["mp4"]).decode(), data_url(MPD), CONTAINERS["mp4"])
        for value in refused:
            with self.subTest(value=value[:40]):
                with self.assertRaises(ValueError):
                    request_url(value, common["inline_media_container"])

    def test_transformers_backend_refuses_raw_video(self):
        hardened = self.hardened["srt/multimodal/processors/transformers_auto.py"]
        self.assertIn("        if video_data:\n            raise ValueError(", hardened)

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
