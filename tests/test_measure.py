from __future__ import annotations

import unittest

from harnesslab.measure import ADVERSARIAL, measure_adversarial


class MeasureTest(unittest.TestCase):
    def test_measure_covers_the_four_adversarial_scenarios(self) -> None:
        report = measure_adversarial(repeats=2)
        self.assertEqual([item["chapter"] for item in report["scenarios"]], [key for key, _ in ADVERSARIAL])
        self.assertTrue(report["totals"]["all_pass"])
        for item in report["scenarios"]:
            self.assertTrue(item["passed"])
            self.assertEqual(item["score"], 1.0)
            self.assertGreater(item["latency_ms_median"], 0)
            self.assertGreater(item["decision_total"], 0)

    def test_measure_counts_one_escalation_across_66_decisions(self) -> None:
        report = measure_adversarial(repeats=2)
        self.assertEqual(report["totals"]["decisions"], 66)
        self.assertEqual(report["totals"]["escalations"], 1)


if __name__ == "__main__":
    unittest.main()
