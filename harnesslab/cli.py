"""Command-line interface for Harness-Engineering-Design-Patterns."""

from __future__ import annotations

import argparse
import json
import sys

from .labs import CHAPTERS, run_all_labs, run_lab
from .measure import measure_adversarial
from .pipeline import demo as pipeline_demo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="harnesslab", description="Run Harness-Engineering-Design-Patterns chapter scenarios.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="List available chapter labs.")
    run = sub.add_parser("run", help="Run a chapter lab or all labs.")
    run.add_argument("chapter", help="Chapter key such as ch01, or 'all'.")
    run.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    sub.add_parser("pipeline", help="Run one request through the seven-stage reference architecture (benign plus two hostile).")
    measure = sub.add_parser("measure", help="Measure the four adversarial scenarios: completion, latency, human review.")
    measure.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    measure.add_argument("--repeats", type=int, default=20, help="In-process runs per scenario for the latency median (default 20).")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        for chapter in CHAPTERS:
            print(f"{chapter.key}\t{chapter.title}")
        return 0

    if args.command == "run":
        results = run_all_labs() if args.chapter == "all" else [run_lab(args.chapter)]
        if args.json:
            print(json.dumps([result.to_dict() for result in results], indent=2, sort_keys=True))
        else:
            for result in results:
                status = "PASS" if result.passed else "FAIL"
                print(f"{result.chapter} {status} score={result.score:.3f} {result.title}")
                print(f"  {result.summary}")
        return 0 if all(result.passed for result in results) else 1

    if args.command == "pipeline":
        for result in pipeline_demo():
            stages = " -> ".join(f"{stage}:{decision.decision.value}" for stage, decision in result.stage_decisions)
            print(f"{result.run_id} executed={result.executed} state_updated={result.state_updated} latency_ms={result.latency_ms:.1f}")
            print(f"  {stages}")
            if result.stopped_at:
                print(f"  stopped at {result.stopped_at}")
        return 0

    if args.command == "measure":
        report = measure_adversarial(repeats=args.repeats)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            for item in report["scenarios"]:
                status = "PASS" if item["passed"] else "FAIL"
                print(
                    f"{item['chapter']} {status} score={item['score']:.3f} "
                    f"latency_ms={item['latency_ms_median']:.1f} escalations={item['escalations']} "
                    f"decisions={item['decision_total']} {item['scenario']}"
                )
            totals = report["totals"]
            print(f"all_pass={totals['all_pass']} decisions={totals['decisions']} escalations={totals['escalations']}")
        return 0 if report["totals"]["all_pass"] else 1

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

