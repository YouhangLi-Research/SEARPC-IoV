#!/usr/bin/env python3
"""Run dependency-free, zero-argument ``test_*`` functions from one file."""

from __future__ import annotations

import importlib.util
import inspect
import sys
import traceback
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: run_plain_function_tests.py TEST_FILE.py")
    path = Path(sys.argv[1]).resolve()
    sys.path.insert(0, str(path.parent.parent))
    spec = importlib.util.spec_from_file_location("searpc_plain_tests", path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import test file: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    tests = [
        (name, value)
        for name, value in vars(module).items()
        if name.startswith("test_")
        and callable(value)
        and len(inspect.signature(value).parameters) == 0
    ]
    failures = 0
    for name, test in sorted(tests):
        try:
            test()
            print(f"PASS | {name}")
        except Exception:
            failures += 1
            print(f"FAIL | {name}")
            traceback.print_exc()
    print(f"{len(tests) - failures}/{len(tests)} plain-function tests passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
