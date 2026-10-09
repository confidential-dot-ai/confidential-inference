"""Put wheel entries in a fixed order without changing their payloads."""
from pathlib import Path
import os
import sys
import zipfile


def canonicalize(path: Path) -> None:
    with zipfile.ZipFile(path) as source:
        entries = source.infolist()
        names = [entry.filename for entry in entries]
        if len(set(names)) != len(names):
            raise ValueError("The wheel contains duplicate entries.")
        payloads = {entry.filename: source.read(entry) for entry in entries}
    temporary = path.with_suffix(".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=9) as target:
            for entry in sorted(entries, key=lambda value: value.filename):
                # Keep timestamps, permissions, RECORD, and every file byte.
                # A different binary still produces a different image.
                target.writestr(entry, payloads[entry.filename],
                                compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == "__main__":
    for name in sys.argv[1:]:
        canonicalize(Path(name))
