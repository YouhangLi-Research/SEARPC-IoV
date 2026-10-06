import unittest

from twsl_baseline.core import (
    combine_local_and_recommended,
    interaction_frequency,
    local_opinion,
    paper_weighted_event_count,
)
from twsl_baseline.models import Opinion, TWSLConfig


class CoreEquationTests(unittest.TestCase):
    def test_equations_1_and_2(self):
        opinion = local_opinion(3, 1, 0.4, 0.5)
        self.assertAlmostEqual(opinion.belief, 0.3)
        self.assertAlmostEqual(opinion.distrust, 0.1)
        self.assertAlmostEqual(opinion.uncertainty, 0.6)
        self.assertAlmostEqual(opinion.expectation, 0.6)

    def test_zero_evidence_is_vacuous(self):
        opinion = local_opinion(0, 0, 0.4, 0.5)
        self.assertEqual(opinion, Opinion(0.0, 0.0, 1.0, 0.5))

    def test_equation_4_literal_table_parameters(self):
        config = TWSLConfig()
        weighted = paper_weighted_event_count(2, 1, 1, 0, config)
        self.assertAlmostEqual(weighted, 1.2)
        self.assertAlmostEqual(interaction_frequency(weighted, 3.0), 0.4)

    def test_equation_12_consensus(self):
        first = Opinion(0.3, 0.1, 0.6)
        second = Opinion(0.1, 0.3, 0.6)
        combined = combine_local_and_recommended(first, second)
        self.assertAlmostEqual(combined.belief, 2.0 / 7.0)
        self.assertAlmostEqual(combined.distrust, 2.0 / 7.0)
        self.assertAlmostEqual(combined.uncertainty, 3.0 / 7.0)
        self.assertAlmostEqual(combined.expectation, 0.5)

    def test_table_text_conflict_is_explicit(self):
        self.assertTrue(TWSLConfig().paper_text_weight_conflict)
        consistent = TWSLConfig(
            theta_positive=0.4,
            tau_negative=0.6,
            enforce_text_inequalities=True,
        )
        self.assertFalse(consistent.paper_text_weight_conflict)


if __name__ == "__main__":
    unittest.main()

