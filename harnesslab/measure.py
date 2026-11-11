"""Measured adversarial results: one HarnessLab system, four scenarios.

Each scenario is a chapter lab run in-process. The measurement records what
the book's contribution claims: the control that stopped the failure, the
evidence the run produced, and the measured outcome — task completion
(score), harness latency (median of repeated in-process runs), and human
review (decisions escalated to a person).

Run it with ``python -m harnesslab.cli measure``. The numbers it prints are
the numbers the course deck reports; the deck is not the source of truth,
this command is.
"""

from __future__ import annotations

import importlib
import statistics
import time
from collections import Counter

from .labs import get_chapter, run_lab

# The four adversarial scenarios from the course's measured-results slide:
# poisoned context, unauthorized memory write, resume after credentials
# expired, and an external action that cannot simply be rolled back.
ADVERSARIAL: tuple[tuple[str, str], ...] = (
    ("ch05", "Poisoned context"),
    ("ch06", "Unauthorized memory write"),
    ("ch03", "Resume after credentials expired"),
    ("ch08", "External action, no rollback"),
)


def measure_adversarial(repeats: int = 20) -> dict:
    """Measure the four adversarial scenarios and return the report."""
    scenarios = []
    total_decisions = 0
    total_escalations = 0
    for chapter, scenario in ADVERSARIAL:
        result = run_lab(chapter)
        counts = Counter(decision["decision"] for decision in result.to_dict()["decisions"])
        # Latency is the harness run() cost only: in-process, interpreter
        # startup excluded, median over repeated runs.
        module = importlib.import_module(get_chapter(chapter).module)
        module.run()
        samples = []
        for _ in range(repeats):
            started = time.perf_counter()
            module.run()
            samples.append((time.perf_counter() - started) * 1000)
        latency_ms = round(statistics.median(samples), 1)
        escalations = counts.get("escalate", 0)
        total_decisions += sum(counts.values())
        total_escalations += escalations
        scenarios.append(
            {
                "chapter": chapter,
                "scenario": scenario,
                "title": result.title,
                "passed": result.passed,
                "score": result.score,
                "decisions": dict(sorted(counts.items())),
                "decision_total": sum(counts.values()),
                "escalations": escalations,
                "latency_ms_median": latency_ms,
                "latency_runs": repeats,
            }
        )
    return {
        "scenarios": scenarios,
        "totals": {
            "scenarios": len(scenarios),
            "all_pass": all(item["passed"] for item in scenarios),
            "decisions": total_decisions,
            "escalations": total_escalations,
        },
    }
