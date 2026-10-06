#!/usr/bin/env python3
"""Build the repository SHA-256 manifest."""

from __future__ import annotations

from hashlib import sha256
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"
EXCLUDED_ROOTS = {".git", ".venv", "outputs"}
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache"}


def digest(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    return (
        path != MANIFEST
        and relative.parts[0] not in EXCLUDED_ROOTS
        and not any(part in EXCLUDED_PARTS for part in relative.parts)
    )


def main() -> int:
    paths = sorted(path for path in ROOT.rglob("*") if path.is_file() and included(path))
    lines = [f"{digest(path)}  {path.relative_to(ROOT).as_posix()}" for path in paths]
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {MANIFEST.name} for {len(paths)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
