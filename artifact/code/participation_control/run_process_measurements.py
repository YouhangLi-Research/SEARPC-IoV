#!/usr/bin/env python3
"""Compatibility entry point for the maintained process prototype."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

path = Path(__file__).resolve().parents[1] / "scoped_evidence" / "run_process_measurements.py"
name = "searpc_process_prototype_maintained"
spec = spec_from_file_location(name, path)
module = module_from_spec(spec)
sys.modules[name] = module
spec.loader.exec_module(module)
globals().update({key: value for key, value in vars(module).items() if not key.startswith("__")})

if __name__ == "__main__":
    module.main()
