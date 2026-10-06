import json
import tempfile
import unittest
from pathlib import Path

from twsl_baseline.veremi import iter_veremi_receiver_directory


class VeReMiAdapterTests(unittest.TestCase):
    def test_receiver_identity_and_preverdict_mobility_are_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = {
                "rcvTime": 2_000_000_000,
                "sendTime": 1_000_000_000,
                "sender_id": "veh_2",
                "sender_alias": 9,
                "messageID": 4,
                "attacker": 1,
                "sender": {"pos": "1,2,0", "spd": 3.0, "hed": 90.0},
                "receiver": {"pos": [4, 5, 0], "spd": 6.0, "hed": 180.0},
            }
            (root / "veh_1.json").write_text(json.dumps([row]), encoding="utf-8")
            message = next(iter_veremi_receiver_directory(root))
            self.assertEqual(message.receiver_id, "veh_1")
            self.assertEqual(message.provider_id, "veh_2")
            self.assertEqual(message.receive_time, 2.0)
            self.assertEqual(message.sender_point.timestamp, 1.0)
            self.assertAlmostEqual(message.receiver_point.direction, 3.141592653589793)


if __name__ == "__main__":
    unittest.main()
