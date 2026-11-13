"""Tests for the lab score: it must measure the scenario's own expectations.

The score is the fraction of expected outcomes that held. It is 1.0 only
when every check passed, drops when a control fails, and is 0.0 with no
checks. A score that cannot move is not a measurement.
"""

import unittest

from harnesslab.core import score_from_checks


class TestScoreFromChecks(unittest.TestCase):
    def test_all_checks_pass(self):
        self.assertEqual(score_from_checks([True, True, True]), 1.0)

    def test_one_check_fails(self):
        self.assertEqual(score_from_checks([True, False, True]), 0.667)

    def test_single_failing_check(self):
        self.assertEqual(score_from_checks([False]), 0.0)

    def test_no_checks(self):
        self.assertEqual(score_from_checks([]), 0.0)

    def test_dict_values_work(self):
        self.assertEqual(score_from_checks({"a": True, "b": False}.values()), 0.5)


if __name__ == "__main__":
    unittest.main()
