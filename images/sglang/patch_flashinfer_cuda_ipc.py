#!/usr/bin/env python3
"""Make FlashInfer select a complete CUDA runtime instead of a JIT stub."""

from pathlib import Path
import sys


TARGET = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(
    "/usr/local/lib/python3.12/dist-packages/flashinfer/comm/cuda_ipc.py"
)

OLD_IMPORT = """import ctypes
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
"""

NEW_IMPORT = """import ctypes
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
"""

OLD_FUNCTION = '''def find_loaded_library(lib_name) -> Optional[str]:
    """
    According to according to https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html,
    the file `/proc/self/maps` contains the memory maps of the process, which includes the
    shared libraries loaded by the process. We can use this file to find the path of the
    a loaded library.
    """  # noqa
    found = False
    with open("/proc/self/maps") as f:
        for line in f:
            if lib_name in line:
                found = True
                break
    if not found:
        # the library is not loaded in the current process
        return None
    # if lib_name is libcudart, we need to match a line with:
    # address /path/to/libcudart-hash.so.11.0
    start = line.index("/")
    path = line[start:].strip()
    filename = path.split("/")[-1]
    assert filename.rpartition(".so")[0].startswith(lib_name), (
        f"Unexpected filename: {filename} for library {lib_name}"
    )
    return path
'''

NEW_FUNCTION = '''def find_loaded_library(lib_name) -> Optional[str]:
    """Return one loaded, complete runtime library."""
    if lib_name == "libcudart":
        for path in (
            "/usr/local/cuda/targets/x86_64-linux/lib/libcudart.so",
            "/usr/local/cuda/lib64/libcudart.so",
        ):
            if not os.path.isfile(path):
                continue
            library = ctypes.CDLL(path)
            if getattr(library, "cudaDeviceReset", None) is not None:
                resolved = os.path.realpath(path)
                logger.info("Using canonical CUDA runtime: %s", resolved)
                return resolved

    candidates = []
    with open("/proc/self/maps") as handle:
        for line in handle:
            if lib_name not in line or "/" not in line:
                continue
            path = line[line.index("/") :].strip()
            if path.endswith(" (deleted)"):
                path = path[: -len(" (deleted)")]
            filename = os.path.basename(path)
            if filename.rpartition(".so")[0].startswith(lib_name):
                candidates.append(path)
    for path in candidates:
        if "stub" in os.path.basename(path):
            continue
        library = ctypes.CDLL(path)
        if getattr(library, "cudaDeviceReset", None) is not None:
            return path
    return candidates[0] if candidates else None
'''


def replace_exact(content: str, old: str, new: str, label: str) -> str:
    if content.count(old) != 1:
        raise SystemExit(f"expected exactly one {label} block")
    return content.replace(old, new)


def main() -> None:
    content = TARGET.read_text(encoding="utf-8")
    content = replace_exact(content, OLD_IMPORT, NEW_IMPORT, "import")
    content = replace_exact(content, OLD_FUNCTION, NEW_FUNCTION, "function")
    compile(content, str(TARGET), "exec")
    TARGET.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()
