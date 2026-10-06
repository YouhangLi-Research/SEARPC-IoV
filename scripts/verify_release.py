#!/usr/bin/env python3
"""Verify file integrity and public-release hygiene."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"


def digest(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def verify_manifest() -> int:
    if not MANIFEST.is_file():
        raise FileNotFoundError("MANIFEST.sha256 is missing")
    count = 0
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        path = ROOT / relative
        if not path.is_file():
            raise AssertionError(f"manifest file is missing: {relative}")
        observed = digest(path)
        if observed != expected:
            raise AssertionError(f"manifest hash mismatch: {relative}")
        count += 1
    return count


def verify_public_text() -> None:
    suffixes = {".md", ".py", ".json", ".yml", ".yaml", ".toml", ".txt", ".cff"}
    paths = [p for p in ROOT.rglob("*") if p.is_file() and p.suffix in suffixes
             and p.relative_to(ROOT).parts[0] not in {"outputs", ".venv", ".git"}
             and "__pycache__" not in p.parts]
    forbidden = (
        "/workspace/" + "scratch/",
        "chat" + "gpt",
        "co" + "dex",
        "internal " + "discussion",
        "内部" + "讨论",
        "to" + "do:",
        "fix" + "me:",
        "re" + "cap",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if token in text:
                raise AssertionError(f"non-public text token {token!r} in {path.relative_to(ROOT)}")
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    for path in (ROOT / "paper").glob("*.docx"):
        with ZipFile(path) as archive:
            if any("comments" in name.lower() for name in archive.namelist()):
                raise AssertionError(f"document comments remain: {path.name}")
            document = ET.fromstring(archive.read("word/document.xml"))
            if document.findall(".//w:ins", ns) or document.findall(".//w:del", ns):
                raise AssertionError(f"tracked changes remain: {path.name}")
            for name in archive.namelist():
                if name.startswith("word/media/") and not archive.read(name):
                    raise AssertionError(f"empty manuscript artwork: {path.name}, {name}")


def main() -> int:
    count = verify_manifest()
    verify_public_text()
    print(f"Release integrity: PASS ({count} files verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
