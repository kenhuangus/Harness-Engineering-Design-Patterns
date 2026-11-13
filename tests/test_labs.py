from __future__ import annotations

import json
import unittest
from pathlib import Path

from harnesslab.labs import CHAPTERS, run_all_labs, run_lab

_REPO_ROOT = Path(__file__).resolve().parent.parent


class LabExecutionTest(unittest.TestCase):
    def test_all_registered_labs_run(self) -> None:
        results = run_all_labs()
        self.assertEqual(len(results), 10)
        for result in results:
            self.assertTrue(result.passed, result.to_json())
            self.assertGreaterEqual(result.score, 0.8, result.to_json())
            self.assertTrue(result.decisions, result.to_json())
            self.assertTrue(result.artifacts, result.to_json())

    def test_each_lab_matches_committed_result(self) -> None:
        """A live run must reproduce the committed LabResult score and pass flag.

        The committed files are the record of what the labs claim. If the
        score moves, either a control regressed or the claim changed — both
        must be a deliberate, reviewed change, not silent drift.
        """
        for chapter in CHAPTERS:
            with self.subTest(chapter=chapter.key):
                committed = json.loads(
                    (_REPO_ROOT / "chapters" / chapter.key / "LabResult" / "result.json").read_text()
                )
                result = run_lab(chapter.key)
                self.assertEqual(result.passed, committed["passed"], result.to_json())
                self.assertEqual(result.score, committed["score"], result.to_json())

    def test_each_lab_matches_registry_key(self) -> None:
        for chapter in CHAPTERS:
            with self.subTest(chapter=chapter.key):
                result = run_lab(chapter.key)
                self.assertEqual(result.chapter, chapter.key)
                self.assertEqual(result.title, chapter.title)


if __name__ == "__main__":
    unittest.main()

