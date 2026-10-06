import unittest

from twsl_baseline.models import Interaction, TrajectoryPoint, TWSLConfig
from twsl_baseline.pipeline import build_local_opinions, compute_reputations


class PipelineTests(unittest.TestCase):
    def test_two_requestors_supply_recommendations(self):
        interactions = [
            Interaction(0, "r1", "p", True, 0.4),
            Interaction(1, "r1", "p", True, 0.4),
            Interaction(0, "r2", "p", False, 0.4),
            Interaction(1, "r2", "p", False, 0.4),
        ]
        trajectories = []
        for vehicle, y in (("r1", 0), ("r2", 1), ("p", 0)):
            trajectories.extend(
                [
                    TrajectoryPoint(0, vehicle, 0, y, 10, 0),
                    TrajectoryPoint(1, vehicle, 1, y, 10, 0),
                ]
            )
        config = TWSLConfig()
        local = build_local_opinions(interactions, trajectories, config, 1)
        self.assertEqual(len(local), 2)
        final = compute_reputations(local, config.gamma)
        self.assertEqual(len(final), 2)
        self.assertTrue(all(item.recommendation_count == 1 for item in final))
        self.assertLess(final[0].final_opinion.uncertainty, final[0].local_opinion.uncertainty)

    def test_finite_window_excludes_old_events_and_trajectory_points(self):
        interactions = [
            Interaction(0, "r", "p", False, 0.5),
            Interaction(1000, "r", "p", True, 0.5),
        ]
        trajectories = [
            TrajectoryPoint(0, "r", 50, 50, 10, 0),
            TrajectoryPoint(0, "p", -50, -50, 10, 0),
            TrajectoryPoint(1000, "r", 0, 0, 10, 0),
            TrajectoryPoint(1000, "p", 0, 0, 10, 0),
        ]
        config = TWSLConfig(
            evaluation_protocol="veremi_adapted",
            history_window_seconds=900,
        )
        local = build_local_opinions(interactions, trajectories, config, 1000)
        self.assertEqual(local[0].positive_events, 1)
        self.assertEqual(local[0].negative_events, 0)
        self.assertEqual(local[0].trajectory_similarity, 1.0)


if __name__ == "__main__":
    unittest.main()
