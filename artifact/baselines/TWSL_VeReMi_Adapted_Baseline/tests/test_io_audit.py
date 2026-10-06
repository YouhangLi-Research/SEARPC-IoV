import csv
import json
import tempfile
import unittest
from pathlib import Path

from twsl_baseline.cli import main
from twsl_baseline.io import read_local_opinions
from twsl_baseline.models import TWSLConfig


class FuseWeightAuditTests(unittest.TestCase):
    def _write_opinions(self, root: Path, weight: float) -> Path:
        path = root / "opinions.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(
                handle,
                fieldnames=[
                    "requestor_id",
                    "provider_id",
                    "belief",
                    "distrust",
                    "uncertainty",
                    "interaction_frequency",
                    "trajectory_similarity",
                    "weight",
                ],
            )
            writer.writeheader()
            writer.writerow(
                {
                    "requestor_id": "r",
                    "provider_id": "p",
                    "belief": 0.2,
                    "distrust": 0.3,
                    "uncertainty": 0.5,
                    "interaction_frequency": 0.0,
                    "trajectory_similarity": 0.0,
                    "weight": weight,
                }
            )
        return path

    def test_forged_external_weight_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_opinions(Path(directory), 999.0)
            with self.assertRaisesRegex(ValueError, r"violates TWSL Eq\. \(10\)"):
                read_local_opinions(path, TWSLConfig())

    def test_equation_10_weight_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_opinions(Path(directory), 0.0)
            records = read_local_opinions(path, TWSLConfig())
            self.assertEqual(records[0].weight, 0.0)

    def test_adapted_manifest_is_labeled_automatically(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            opinions = self._write_opinions(root, 0.0)
            config = root / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "evaluation_protocol": "veremi_adapted",
                        "history_window_seconds": 900.0,
                    }
                ),
                encoding="utf-8",
            )
            output = root / "output"
            self.assertEqual(
                main(
                    [
                        "fuse",
                        "--opinions",
                        str(opinions),
                        "--config",
                        str(config),
                        "--out-dir",
                        str(output),
                    ]
                ),
                0,
            )
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "veremi_adapted_reimplementation")
            self.assertEqual(manifest["external_weight_policy"], "strict_eq10_validation")


if __name__ == "__main__":
    unittest.main()
