#!/usr/bin/env python3
"""Check that every relative link in a Markdown file points at a real file.

This is the fast check the "docs-only" CI job runs. It does not fetch any
network address; it only resolves relative links (and anchors that point at
a heading in the target file) against the files this repository tracks.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Matches a Markdown link target: the "(...)" part of "[text](target)".
LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

# A heading turns into a GitHub anchor by lowercasing it, dropping any
# character that is not a letter, digit, space, or hyphen, and replacing
# each run of spaces with one hyphen.
HEADING_PATTERN = re.compile(r"^#{1,6}\s+(.*)$", re.MULTILINE)


def heading_anchor(heading: str) -> str:
    slug = heading.strip().lower()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"\s+", "-", slug)
    return slug


def anchors_in(markdown_file: Path) -> set[str]:
    text = markdown_file.read_text(encoding="utf-8")
    return {heading_anchor(heading) for heading in HEADING_PATTERN.findall(text)}


def is_vendored(relative_path: str) -> bool:
    # A "*-upstream/" directory (for example images/sglang/simulator-upstream)
    # holds an unmodified copy of another project's source. Its Markdown
    # links point at files in that project's own tree, not this repository's
    # tree, so this check does not apply to it.
    return any(part.endswith("-upstream") for part in Path(relative_path).parts)


def tracked_markdown_files() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [ROOT / line for line in output.splitlines() if line and not is_vendored(line)]


def is_external(target: str) -> bool:
    return bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target)) or target.startswith("mailto:")


def check_file(markdown_file: Path) -> list[str]:
    errors: list[str] = []
    text = markdown_file.read_text(encoding="utf-8")
    for target in LINK_PATTERN.findall(text):
        target = target.split(" ", 1)[0].strip()  # drop an optional "title"
        if not target or is_external(target):
            continue

        path_part, _, fragment = target.partition("#")
        if not path_part:
            # A pure "#anchor" link: check it against this file's own headings.
            if fragment and fragment not in anchors_in(markdown_file):
                errors.append(f"{markdown_file}: no heading matches anchor '#{fragment}'")
            continue

        resolved = (markdown_file.parent / path_part).resolve()
        if not resolved.exists():
            errors.append(f"{markdown_file}: link target does not exist: {path_part}")
            continue

        if fragment and resolved.suffix == ".md" and fragment not in anchors_in(resolved):
            errors.append(f"{markdown_file}: no heading in {path_part} matches anchor '#{fragment}'")

    return errors


def main() -> int:
    errors: list[str] = []
    for markdown_file in tracked_markdown_files():
        errors.extend(check_file(markdown_file))

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"{len(errors)} broken Markdown link(s) found.", file=sys.stderr)
        return 1

    print("All Markdown links resolve.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
