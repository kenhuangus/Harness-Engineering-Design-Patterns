"""Chapter 7 observability scenario.

The lab is deterministic and dependency-free. It models the evidence a secure
agent harness should produce when it observes a long-running agent, protects the
evidence stream, detects benchmark regressions, and governs self-improvement.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from harnesslab.core import (
    ActionRisk,
    DataClass,
    Decision,
    EvidenceEnvelope,
    LabResult,
    PolicyDecision,
    ToolCall,
    TraceSpan,
    score_from_checks,
    stable_id,
)


CHAPTER = "ch07"
TITLE = "Observability, Evals, and Hill-Climbing Evidence"
RUN_ID = "ch07-observability-training-run"
ACTOR = "observer-agent"
POLICY_VERSION = "observability-policy-v1"
FIXED_TIME = 1_760_000_000.0

EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
TOKEN_PATTERN = re.compile(r"\b(token=|sk_live_)[A-Za-z0-9_.:=/-]+\b")
SENSITIVE_KEYS = {"customer_email", "api_token", "secret", "password"}


def _stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _redact_payload(payload: Any) -> tuple[Any, list[str]]:
    redactions: list[str] = []

    def remember(marker: str) -> None:
        if marker not in redactions:
            redactions.append(marker)

    def redact(value: Any, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {item_key: redact(item_value, item_key) for item_key, item_value in value.items()}
        if isinstance(value, list):
            return [redact(item) for item in value]
        if not isinstance(value, str):
            return value

        if key in SENSITIVE_KEYS:
            remember(f"field:{key}")
            if "email" in key:
                return "[REDACTED_EMAIL]"
            return "[REDACTED_SECRET]"

        result = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", value)
        if result != value:
            remember("pattern:email")
        next_result = TOKEN_PATTERN.sub("[REDACTED_TOKEN]", result)
        if next_result != result:
            remember("pattern:token")
        return next_result

    return redact(payload), redactions


def _metric_score(metrics: dict[str, float]) -> float:
    latency_penalty = max(metrics["median_latency_ms"] - 900.0, 0.0) / 10_000.0
    return round(
        metrics["task_success"] * 0.35
        + metrics["unsafe_block_rate"] * 0.30
        + metrics["redaction_recall"] * 0.20
        + metrics["replay_pass_rate"] * 0.15
        - latency_penalty,
        4,
    )


def _regression_report(baseline: dict[str, float], candidate: dict[str, float]) -> dict[str, Any]:
    safety_metrics = ("unsafe_block_rate", "redaction_recall", "replay_pass_rate")
    deltas = {name: round(candidate[name] - baseline[name], 4) for name in baseline}
    failed = [name for name in safety_metrics if deltas[name] < 0]
    return {
        "baseline": baseline,
        "candidate": candidate,
        "deltas": deltas,
        "failed_gates": failed,
        "verdict": "escalate" if failed else "pass",
    }


def _serialize_spans(spans: list[TraceSpan]) -> list[dict[str, Any]]:
    return [
        {
            "span_id": span.span_id,
            "name": span.name,
            "started_at": span.started_at,
            "ended_at": span.ended_at,
            "attributes": span.attributes,
            "events": span.events,
        }
        for span in spans
    ]


def _build_spans(redactions: list[str], best_candidate: str) -> list[TraceSpan]:
    return [
        TraceSpan(
            span_id=stable_id("span", RUN_ID, "observe.tool_call", "0"),
            name="observe.tool_call",
            started_at=FIXED_TIME,
            ended_at=FIXED_TIME + 0.010,
            attributes={
                "intent": "notify customer after incident review",
                "tool": "send_customer_email",
                "data_class": DataClass.PII.value,
                "decision": Decision.REWRITE.value,
            },
            events=[
                {
                    "name": "policy.decision",
                    "at": FIXED_TIME + 0.002,
                    "attributes": {
                        "decision": Decision.REWRITE.value,
                        "reason": "sensitive fields redacted before evidence emission",
                    },
                }
            ],
        ),
        TraceSpan(
            span_id=stable_id("span", RUN_ID, "observe.evidence", "1"),
            name="observe.evidence",
            started_at=FIXED_TIME + 0.020,
            ended_at=FIXED_TIME + 0.030,
            attributes={"policy_version": POLICY_VERSION, "redaction_count": len(redactions)},
            events=[
                {
                    "name": "evidence.redacted",
                    "at": FIXED_TIME + 0.024,
                    "attributes": {"redactions": redactions},
                },
                {
                    "name": "artifact.hashes.computed",
                    "at": FIXED_TIME + 0.028,
                    "attributes": {"hash_algorithm": "sha256"},
                },
            ],
        ),
        TraceSpan(
            span_id=stable_id("span", RUN_ID, "observe.eval_loop", "2"),
            name="observe.eval_loop",
            started_at=FIXED_TIME + 0.040,
            ended_at=FIXED_TIME + 0.060,
            attributes={"loop": "hill_climbing", "best_candidate": best_candidate},
            events=[
                {
                    "name": "benchmark.regression_detected",
                    "at": FIXED_TIME + 0.045,
                    "attributes": {"candidate": "aggressive_trace_sampling"},
                },
                {
                    "name": "candidate.accepted",
                    "at": FIXED_TIME + 0.055,
                    "attributes": {"candidate": best_candidate},
                },
            ],
        ),
        TraceSpan(
            span_id=stable_id("span", RUN_ID, "observe.governed_rsi", "3"),
            name="observe.governed_rsi",
            started_at=FIXED_TIME + 0.070,
            ended_at=FIXED_TIME + 0.080,
            attributes={"control": "governed_recursive_self_improvement"},
            events=[
                {
                    "name": "self_improvement.denied",
                    "at": FIXED_TIME + 0.072,
                    "attributes": {"reason": "missing evidence hash and rollback plan"},
                },
                {
                    "name": "self_improvement.approved",
                    "at": FIXED_TIME + 0.078,
                    "attributes": {"scope": "bounded redaction-before-indexing rollout"},
                },
            ],
        ),
    ]


def _hill_climb() -> dict[str, Any]:
    baseline = {
        "task_success": 0.84,
        "unsafe_block_rate": 1.00,
        "redaction_recall": 1.00,
        "replay_pass_rate": 1.00,
        "median_latency_ms": 910.0,
    }
    candidates = [
        {
            "candidate": "decision_reason_capture",
            "change": "Attach policy reason and evidence requirement to every trace span.",
            "metrics": {
                "task_success": 0.85,
                "unsafe_block_rate": 1.00,
                "redaction_recall": 1.00,
                "replay_pass_rate": 1.00,
                "median_latency_ms": 930.0,
            },
        },
        {
            "candidate": "aggressive_trace_sampling",
            "change": "Drop most trace payloads to reduce median latency.",
            "metrics": {
                "task_success": 0.88,
                "unsafe_block_rate": 0.96,
                "redaction_recall": 0.98,
                "replay_pass_rate": 0.88,
                "median_latency_ms": 620.0,
            },
        },
        {
            "candidate": "redact_before_indexing",
            "change": "Redact evidence before indexing it into replay and search stores.",
            "metrics": {
                "task_success": 0.86,
                "unsafe_block_rate": 1.00,
                "redaction_recall": 1.00,
                "replay_pass_rate": 1.00,
                "median_latency_ms": 940.0,
            },
        },
    ]

    incumbent = {
        "candidate": "baseline",
        "metrics": baseline,
        "score": _metric_score(baseline),
    }
    iterations: list[dict[str, Any]] = []
    for index, candidate in enumerate(candidates, start=1):
        report = _regression_report(incumbent["metrics"], candidate["metrics"])
        score = _metric_score(candidate["metrics"])
        safe = not report["failed_gates"]
        accepted = safe and score > incumbent["score"]
        iterations.append(
            {
                "iteration": index,
                "candidate": candidate["candidate"],
                "change": candidate["change"],
                "metrics": candidate["metrics"],
                "score": score,
                "regression_gates": report["failed_gates"],
                "accepted": accepted,
            }
        )
        if accepted:
            incumbent = {
                "candidate": candidate["candidate"],
                "metrics": candidate["metrics"],
                "score": score,
            }

    return {
        "baseline": baseline,
        "iterations": iterations,
        "selected": incumbent,
    }


def run() -> LabResult:
    raw_observation = {
        "ticket_id": "INC-407",
        "tool": "send_customer_email",
        "intent": "notify customer after incident review",
        "customer_email": "alex.customer@example.com",
        "draft": "Notify the customer that the incident is closed. Never log token=sk_live_training_secret.",
        "data_class": DataClass.PII.value,
    }
    redacted_observation, redactions = _redact_payload(raw_observation)

    redacted_trace_call = ToolCall(
        tool="emit_trace",
        args=redacted_observation,
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.READ,
        intent="emit redacted observability evidence",
    )

    baseline = {
        "task_success": 0.84,
        "unsafe_block_rate": 1.00,
        "redaction_recall": 1.00,
        "replay_pass_rate": 1.00,
        "median_latency_ms": 910.0,
    }
    regressed_candidate = {
        "task_success": 0.88,
        "unsafe_block_rate": 0.96,
        "redaction_recall": 0.98,
        "replay_pass_rate": 0.88,
        "median_latency_ms": 620.0,
    }
    benchmark_regression = _regression_report(baseline, regressed_candidate)
    hill_climb = _hill_climb()

    governed_rsi = {
        "denied_attempt": {
            "proposal_id": stable_id("rsi", RUN_ID, "unguarded-weight-change"),
            "requested_change": "raise task-success weight and ignore replay failures",
            "status": "denied",
            "missing_controls": ["evidence_hash", "rollback_checkpoint", "human_approval"],
        },
        "approved_attempt": {
            "proposal_id": stable_id("rsi", RUN_ID, "redact-before-indexing"),
            "requested_change": "promote redaction-before-indexing after safe eval improvement",
            "status": "approved_for_supervised_rollout",
            "evidence_hash": _stable_hash(hill_climb),
            "rollback_checkpoint": stable_id("ckpt", RUN_ID, "redact-before-indexing"),
            "required_controls": [
                "regression_suite_passed",
                "tamper_evident_evidence",
                "bounded_rollout",
                "human_change_ticket",
            ],
        },
    }

    spans = _build_spans(redactions, hill_climb["selected"]["candidate"])
    serialized_spans = _serialize_spans(spans)
    decision_trace = [
        {
            "step": "observe",
            "decision": Decision.ALLOW.value,
            "reason": "tool call was captured with intent, data class, and policy context",
            "evidence": spans[0].span_id,
        },
        {
            "step": "redact",
            "decision": Decision.REWRITE.value,
            "reason": "PII and token-like text were removed before evidence emission",
            "evidence": spans[1].span_id,
        },
        {
            "step": "regression",
            "decision": Decision.ESCALATE.value,
            "reason": "benchmark evidence showed lower unsafe-block, redaction, and replay rates",
            "evidence": "benchmark_regression",
        },
        {
            "step": "hill_climb",
            "decision": Decision.ALLOW.value,
            "reason": "safe candidate improved the composite eval score without safety regression",
            "evidence": "hill_climb",
        },
        {
            "step": "recursive_self_improvement",
            "decision": Decision.DENY.value,
            "reason": "unguarded self-modification was blocked",
            "evidence": governed_rsi["denied_attempt"]["proposal_id"],
        },
        {
            "step": "governed_rollout",
            "decision": Decision.ALLOW.value,
            "reason": "bounded self-improvement included evidence, rollback, and approval controls",
            "evidence": governed_rsi["approved_attempt"]["proposal_id"],
        },
    ]

    replay_bundle = {
        "schema": "harnesslab.replay.v1",
        "run_id": RUN_ID,
        "policy_version": POLICY_VERSION,
        "inputs": {
            "raw_observation_hash": _stable_hash(raw_observation),
            "redacted_observation": redacted_observation,
        },
        "trace": serialized_spans,
        "expected_decision_trace": decision_trace,
        "expected_regression_verdict": benchmark_regression["verdict"],
        "expected_selected_candidate": hill_climb["selected"]["candidate"],
    }

    artifact_payloads = {
        "redacted_observation": redacted_observation,
        "decision_trace": decision_trace,
        "trace_spans": serialized_spans,
        "benchmark_regression": benchmark_regression,
        "hill_climb": hill_climb,
        "governed_rsi": governed_rsi,
        "replay_bundle": replay_bundle,
    }
    artifact_hashes = {name: _stable_hash(payload) for name, payload in artifact_payloads.items()}

    envelope = EvidenceEnvelope(
        run_id=RUN_ID,
        actor=ACTOR,
        policy_version=POLICY_VERSION,
        spans=spans,
        artifact_hashes=artifact_hashes,
        redactions=redactions,
        created_at=FIXED_TIME + 0.090,
    )
    envelope_hash = envelope.tamper_evident_hash()

    decisions = [
        PolicyDecision(Decision.ALLOW, "decision trace captured for observed tool call", ("observability", "trace")),
        PolicyDecision(
            Decision.REWRITE,
            "sensitive evidence rewritten before trace emission",
            ("observability", "redaction"),
            rewritten_call=redacted_trace_call,
        ),
        PolicyDecision(Decision.ALLOW, "evidence envelope sealed with artifact hashes", ("observability", "evidence_envelope")),
        PolicyDecision(Decision.ALLOW, "replay bundle assembled from redacted inputs and expected decisions", ("observability", "replay")),
        PolicyDecision(
            Decision.ESCALATE,
            "benchmark regression evidence requires reviewer attention",
            ("evals", "benchmark_regression"),
        ),
        PolicyDecision(Decision.ALLOW, "hill-climbing loop selected a safe eval improvement", ("evals", "hill_climbing")),
        PolicyDecision(
            Decision.DENY,
            "recursive self-improvement without evidence and rollback is blocked",
            ("governance", "recursive_self_improvement"),
        ),
        PolicyDecision(
            Decision.ALLOW,
            "governed recursive self-improvement accepted as bounded rollout",
            ("governance", "bounded_rollout", "rollback"),
        ),
    ]

    redacted_text = json.dumps(redacted_observation, sort_keys=True)
    replay_verified = all(artifact_hashes[name] == _stable_hash(payload) for name, payload in artifact_payloads.items())
    checks = [
        "alex.customer@example.com" not in redacted_text,
        "sk_live_training_secret" not in redacted_text,
        bool(redactions),
        replay_verified,
        benchmark_regression["verdict"] == "escalate",
        hill_climb["selected"]["candidate"] == "redact_before_indexing",
        governed_rsi["denied_attempt"]["status"] == "denied",
        governed_rsi["approved_attempt"]["status"] == "approved_for_supervised_rollout",
    ]
    passed = all(checks)

    return LabResult(
        chapter=CHAPTER,
        title=TITLE,
        passed=passed,
        score=score_from_checks(checks),
        summary=(
            "Observed a risky agent action with redacted traces, sealed evidence, replayable artifacts, "
            "benchmark regression proof, a hill-climbing eval loop, and governed recursive self-improvement."
        ),
        decisions=decisions,
        artifacts={
            **artifact_payloads,
            "artifact_hashes": artifact_hashes,
            "evidence_envelope": {
                "run_id": envelope.run_id,
                "actor": envelope.actor,
                "policy_version": envelope.policy_version,
                "redactions": envelope.redactions,
                "artifact_hashes": envelope.artifact_hashes,
                "tamper_evident_hash": envelope_hash,
            },
            "replay_verified": replay_verified,
        },
    )

