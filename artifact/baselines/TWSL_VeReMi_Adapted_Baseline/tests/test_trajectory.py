import math
import unittest

from twsl_baseline.models import TrajectoryPoint, TWSLConfig
from twsl_baseline.trajectory import (
    direction_dissimilarity,
    lcs_length,
    location_dissimilarity,
    speed_dissimilarity,
    trajectory_similarity,
)


def point(t, x, y, speed=10.0, direction=None, vehicle="v"):
    return TrajectoryPoint(t, vehicle, x, y, speed, direction)


class TrajectoryEquationTests(unittest.TestCase):
    def test_exact_lcs_and_location_equation_8(self):
        first = [point(0, 0, 0), point(1, 1, 0), point(2, 2, 0)]
        second = [point(0, 0, 0), point(1, 2, 0)]
        self.assertEqual(lcs_length(first, second), 2)
        self.assertAlmostEqual(location_dissimilarity(first, second), 1.0 / 3.0)

    def test_speed_equation_7(self):
        first = [point(0, 0, 0, 10), point(1, 1, 0, 10)]
        second = [point(0, 0, 0, 5), point(1, 1, 0, 5)]
        self.assertAlmostEqual(speed_dissimilarity(first, second), 0.5)

    def test_direction_equation_9(self):
        east = [point(0, 0, 0), point(1, 1, 0)]
        north = [point(0, 0, 0), point(1, 0, 1)]
        west = [point(0, 0, 0), point(1, -1, 0)]
        self.assertAlmostEqual(direction_dissimilarity(east, north), 0.5)
        self.assertAlmostEqual(direction_dissimilarity(east, west), 1.0)

    def test_identical_trajectory_similarity_is_one(self):
        segment = [
            point(0, 0, 0, 10, 0),
            point(1, 1, 0, 10, 0),
        ]
        self.assertAlmostEqual(trajectory_similarity(segment, segment, TWSLConfig()), 1.0)


if __name__ == "__main__":
    unittest.main()

