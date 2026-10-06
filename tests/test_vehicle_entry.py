"""Portable entry-point and reporting tests for the vehicle experiments."""

import importlib.util
import itertools
from pathlib import Path
from statistics import mean
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("vehicle_entry", ROOT / "scripts" / "run_vehicle_experiments.py")
vehicle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vehicle)


def brute_pvalue(values):
    values = [x for x in values if abs(x) > 1e-15]
    if not values:
        return 1.0
    observed = abs(mean(values))
    outcomes = [abs(mean([sign*x for sign, x in zip(signs, values)]))
                for signs in itertools.product((-1, 1), repeat=len(values))]
    return sum(outcome >= observed-1e-15 for outcome in outcomes) / len(outcomes)


class VehicleEntryTests(unittest.TestCase):
    def test_exact_input_hashes(self):
        vehicle.verify_inputs()

    def test_reporting_test_matches_enumeration(self):
        for values in ([], [0, 0], [1, 2], [0.1, -0.2, 0.3, -0.7],
                       [1e-16, 0.12, -0.12, 0.03, -0.08, 0.2]):
            self.assertEqual(vehicle.exact_sign_flip(values), brute_pvalue(values))

    def test_unregistered_reuse_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            vehicle.write_json(output / "RUN_CONFIG.json", {"stage": "other"})
            with self.assertRaises(ValueError):
                vehicle.evaluate([], output, {"stage": "role"}, 1, resume=True)

    def test_nonempty_destination_is_protected(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            vehicle.write_json(output / "RUN_CONFIG.json", {"stage": "role"})
            with self.assertRaises(FileExistsError):
                vehicle.evaluate([], output, {"stage": "role"}, 1, resume=False)

    def test_reference_mismatch_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            reference = Path(directory) / "reference.csv"
            vehicle.write_csv(reference, [{"method": "SEARPC", "rate": 0.0}])
            with self.assertRaises(AssertionError):
                vehicle.compare_table([{"method": "SEARPC", "rate": 0.1}], reference, ("method",))


if __name__ == "__main__":
    unittest.main()
