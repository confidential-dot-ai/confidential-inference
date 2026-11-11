#!/usr/bin/env python3
"""Build-time inline-only policy for request-supplied media in the pinned SGLang worker.

Media is accepted only as bytes, a data: URL or raw base64. The URL download
and local-file branches are replaced, not guarded, and Pillow opens only
IMAGE_FORMATS. Source hashes make upstream changes require another review.
"""
import argparse
import ast
import hashlib
from pathlib import Path

IMAGE_FORMATS = ("JPEG", "PNG", "WEBP", "GIF")

SOURCE_HASHES = {
    "srt/utils/common.py": "438714a57af4e897f593acb58504f9b896e4c5a8bbad449877ca9eaae398c47e",
    "srt/utils/video_decoder.py": "6762a7088adbb23b6d299e632c96f8a0dba7a090c6de968cd244f86de5b1f005",
    "srt/multimodal/cache/identity.py": "c29e0524c47814237e6343ebd5ffc1987642392062abfefc2ef611fb4460e331",
    "srt/multimodal/processors/mimo_v2.py": "a9968ea15cfcca33b0740663ae4fe5c87778f914e3a8893fa769ed190f9b8c13",
    "srt/multimodal/processors/mimo_audio.py": "24589332f570e69b9c04085026d3ec9df199d742db8e361fe7d70f92a270a8a1",
    "srt/multimodal/processors/moss_vl.py": "217823d5615d18f58d212c91ee2f9ae4949e643c6c08b24c7c1743f9aa04eaa2",
    "srt/multimodal/processors/inkling.py": "d23c1d67fbd643d5be2390c2a1340a1d21bb64d3c3624b061ef8f01fda041fd2",
    "srt/multimodal/inkling/image_processing.py": "bf11425a3eda1180ef585c0fd0b6461063c608ebe93540bac3a73273872af6bf",
    "srt/multimodal/inkling/feature_extraction.py": "d1f14c50d2a0dddbeb2249c00b6fc1c118b05f65477a9000608d24b36939cd2e",
}

INLINE_ONLY = "Media URLs and paths are not supported; send media inline as a data: URL or base64"

# Whole definitions replaced by qualified name.
DEFINITIONS = {
    "srt/utils/common.py": {
        "_assert_media_url_allowed": f'''\
def _assert_media_url_allowed(url: str) -> None:
    raise ValueError({INLINE_ONLY!r})
''',
        "download_remote_media": f'''\
def download_remote_media(url: str, timeout: float) -> bytes:
    raise ValueError({INLINE_ONLY!r})
''',
        "get_mm_http_session": f'''\
def get_mm_http_session() -> requests.Session:
    raise ValueError({INLINE_ONLY!r})
''',
        "load_image": '''\
def load_image(
    image_file: Union[Image.Image, str, ImageData, bytes],
    gpu_image_decode: GPUImageDecodeMode = True,
) -> tuple[Union[torch.Tensor, Image.Image], Optional[tuple[int, int]]]:
    """Load an image given as ImageData, a PIL Image, bytes, a data: URL or base64."""
    if isinstance(image_file, ImageData):
        image_file = image_file.url
    if isinstance(image_file, Image.Image):
        image = _fully_load_pil_image(image_file)
        return image, (image.width, image.height)
    if isinstance(image_file, (bytes, str)):
        image_bytes = inline_media_bytes(image_file)
        return _load_image(image_bytes=image_bytes, gpu_image_decode=gpu_image_decode), None
    raise ValueError(f"Invalid image: {image_file}")
''',
        "get_image_bytes": f'''\
IMAGE_FORMATS = {IMAGE_FORMATS!r}
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")


def inline_media_bytes(media: Union[str, bytes]) -> bytes:
    """Decode media given inline as bytes, a data: URL or raw base64.

    Any other string, such as a URL or a path, raises ValueError without
    network or filesystem access.
    """
    if isinstance(media, (bytes, bytearray, memoryview)):
        return bytes(media)
    if not isinstance(media, str):
        raise ValueError(f"Unsupported media input type: {{type(media).__name__}}")
    if media.startswith("data:"):
        _, separator, encoded = media.partition(",")
        if not separator:
            raise ValueError("Invalid media data URL")
        return pybase64.b64decode(encoded, validate=True)
    if _URL_SCHEME.match(media):
        raise ValueError({INLINE_ONLY!r})
    return pybase64.b64decode(media, validate=True)


def get_image_bytes(image_file: Union[str, bytes]) -> bytes:
    """Normalize an inline image input into raw bytes."""
    return inline_media_bytes(image_file)


def _open_allowed_image(fp, mode="r", formats=None):
    allowed = [name for name in formats or IMAGE_FORMATS if name.upper() in IMAGE_FORMATS]
    return _open_any_image(fp, mode, allowed)


# Every Image.open in the worker, including model-specific processors.
_open_any_image = Image.open
Image.open = _open_allowed_image
''',
        "_normalize_video_input": '''\
def _normalize_video_input(video_file: Union[str, bytes]) -> bytes:
    """Decode an inline video input to bytes."""
    return inline_media_bytes(video_file)
''',
        "get_video_bytes": '''\
def get_video_bytes(video_file: Union[str, bytes, VideoData]) -> bytes:
    """Decode an inline video input to its encoded bytes."""
    if isinstance(video_file, VideoData):
        video_file = video_file.url
    return inline_media_bytes(video_file)
''',
    },
    "srt/multimodal/cache/identity.py": {
        "_read_media_bytes": '''\
def _read_media_bytes(media: str | bytes) -> bytes:
    from sglang.srt.utils.common import inline_media_bytes

    return inline_media_bytes(media)
''',
    },
}

# Exact (old, new) text edits; each old text occurs once in the pinned source.
TEXT_EDITS = {
    "srt/utils/common.py": [
        ("        image = Image.open(BytesIO(image_bytes))\n",
         "        image = Image.open(BytesIO(image_bytes), formats=IMAGE_FORMATS)\n"),
        ('''\
    # Normalize input: resolve URL / base64 / file:// to bytes or path
    if isinstance(audio_file, bytes):
        source = audio_file
    elif isinstance(audio_file, str) and audio_file.startswith("data:"):
        source = pybase64.b64decode(audio_file.split(",")[1], validate=True)
    elif isinstance(audio_file, str) and (
        audio_file.startswith("http://") or audio_file.startswith("https://")
    ):
        timeout = int(os.getenv("REQUEST_TIMEOUT", "5"))
        source = download_remote_media(audio_file, timeout=timeout)
    elif isinstance(audio_file, str) and audio_file.startswith("file://"):
        source = unquote(urlparse(audio_file).path)
    elif isinstance(audio_file, str):
        source = audio_file
    else:
        raise ValueError(f"Invalid audio format: {audio_file}")
''', "    source = inline_media_bytes(audio_file)\n"),
        ('''\
    if isinstance(source, bytes):
        header = source[:16]
    else:
        with open(source, "rb") as audio_stream:
            header = audio_stream.read(16)
''', "    header = source[:16]\n"),
    ],
    "srt/utils/video_decoder.py": [
        ('''\
        self._source = source
        self._num_decode_threads = num_decode_threads
''', f'''\
        if not isinstance(source, bytes):
            raise ValueError({INLINE_ONLY!r})
        self._source = source
        self._num_decode_threads = num_decode_threads
'''),
    ],
    "srt/multimodal/processors/mimo_v2.py": [
        ("from sglang.srt.utils.common import download_remote_media\n",
         "from sglang.srt.utils.common import inline_media_bytes\n"),
        ('''\
        # Never hand a client-supplied URL to ffprobe: its internal HTTP client
        # would bypass the shared domain and redirect policy. Resolve it through
        # the guarded downloader first, then probe the resulting bytes in-process.
        if isinstance(path_or_data, str) and path_or_data.startswith(
            ("http://", "https://")
        ):
            timeout = int(os.getenv("REQUEST_TIMEOUT", "10"))
            path_or_data = download_remote_media(path_or_data, timeout=timeout)

        if isinstance(path_or_data, bytes):
            source = BytesIO(path_or_data)
        elif (
            isinstance(path_or_data, str)
            and path_or_data.startswith("data:")
            and ";base64," in path_or_data
        ):
            source = BytesIO(base64.b64decode(path_or_data.split(";base64,")[1]))
        else:
            source = path_or_data  # local path or file://
''', "        source = BytesIO(inline_media_bytes(path_or_data))\n"),
        ('''\
        elif isinstance(image, str):
            if image.startswith("http://") or image.startswith("https://"):
                with BytesIO(download_remote_media(image, timeout=3)) as bio:
                    image_obj = copy.deepcopy(Image.open(bio))
            elif image.startswith("file://"):
                image_obj = Image.open(image[7:])
            elif image.startswith("data:image"):
                if "base64," in image:
                    _, base64_data = image.split("base64,", 1)
                    data = base64.b64decode(base64_data)
                    with BytesIO(data) as bio:
                        image_obj = copy.deepcopy(Image.open(bio))
            else:
                image_obj = Image.open(image)
''', '''\
        elif isinstance(image, str):
            image_obj = Image.open(BytesIO(inline_media_bytes(image)))
'''),
    ],
    "srt/multimodal/processors/mimo_audio.py": [
        ('''\
                elif audio.startswith("http://") or audio.startswith("https://"):
                    dl_start = time.perf_counter()
                    timeout = int(os.getenv("REQUEST_TIMEOUT", "5"))
                    try:
                        content = common.download_remote_media(audio, timeout=timeout)
                        dl_elapsed_ms = (time.perf_counter() - dl_start) * 1000
                        if dl_elapsed_ms > 1000.0:
                            logger.warning(
                                f"Slow audio download: {dl_elapsed_ms:.2f}ms, "
                                f"size={len(content) / 1024:.1f}KB, url={audio}"
                            )
                        file = io.BytesIO(content)
                    except Exception as e:
                        dl_elapsed_ms = (time.perf_counter() - dl_start) * 1000
                        logger.error(
                            f"Failed to download audio: {dl_elapsed_ms:.2f}ms, "
                            f"error={type(e).__name__}: {e}, url={audio}"
                        )
                        raise
                else:
                    file = audio
''', '''\
                else:
                    file = io.BytesIO(common.inline_media_bytes(audio))
'''),
    ],
    "srt/multimodal/processors/moss_vl.py": [
        ('''\
        if value.startswith("file://"):
            return self._resolve_file_url(value), None

        if os.path.isfile(value):
            return value, None

        if value.startswith(("http://", "https://")):
            timeout = int(os.getenv("REQUEST_TIMEOUT", "10"))
            content = download_remote_media(value, timeout=timeout)
            suffix = os.path.splitext(urlparse(value).path)[1] or ".mp4"
            temp_path = self._write_video_bytes_to_tempfile(content, suffix=suffix)
            return temp_path, temp_path

''', ""),
    ],
    "srt/multimodal/processors/inkling.py": [
        ("from sglang.srt.utils.common import download_remote_media\n",
         "from sglang.srt.utils.common import inline_media_bytes\n"),
        ('''\
    if url.startswith(("http://", "https://")):
        return download_remote_media(url, timeout=30)
    return url  # plain path / file:// -> handled by the per-modality byte loader
''', "    return inline_media_bytes(url)\n"),
    ],
    "srt/multimodal/inkling/image_processing.py": [
        ('''\
        path = image[len("file://") :] if image.startswith("file://") else image
        with open(path, "rb") as f:
            return f.read()
''', f"        raise ValueError({INLINE_ONLY!r})\n"),
    ],
    "srt/multimodal/inkling/feature_extraction.py": [
        ('''\
        path = audio[len("file://") :] if audio.startswith("file://") else audio
        with open(path, "rb") as f:
            return f.read()
''', f"        raise ValueError({INLINE_ONLY!r})\n"),
    ],
}


def definition(tree, qualname):
    scope, node = tree.body, None
    for name in qualname.split("."):
        matches = [n for n in scope if isinstance(n, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                   and n.name == name]
        if len(matches) != 1:
            raise ValueError(f"expected one definition of {qualname}")
        node = matches[0]
        scope = node.body
    return node


def harden(path, source):
    tree = ast.parse(source)
    spans = []
    for qualname, replacement in DEFINITIONS.get(path, {}).items():
        node = definition(tree, qualname)
        start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
        spans.append((start, node.end_lineno, replacement))
    lines = source.splitlines(keepends=True)
    for start, end, replacement in sorted(spans, reverse=True):
        lines[start - 1:end] = [replacement]
    result = "".join(lines)
    for old, new in TEXT_EDITS.get(path, []):
        if result.count(old) != 1:
            raise ValueError(f"unsupported {path} source; review media policy before building")
        result = result.replace(old, new)
    compile(result, path, "exec")
    return result


def patch(root):
    sources = {path: (root / path).read_text() for path in SOURCE_HASHES}
    for path, source in sources.items():
        if hashlib.sha256(source.encode()).hexdigest() != SOURCE_HASHES[path]:
            raise ValueError(f"unsupported {path} source; review media policy before building")
    for path, source in sources.items():
        (root / path).write_text(harden(path, source))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="sglang Python package directory")
    patch(parser.parse_args().root)
