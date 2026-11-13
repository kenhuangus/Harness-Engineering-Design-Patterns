from __future__ import annotations

import hashlib
import time

from harnesslab.core import (
    ActionRisk,
    DataClass,
    Decision,
    Harness,
    IntentContract,
    LabResult,
    PolicyDecision,
    ToolCall,
    score_from_checks,
)


TITLE = "Intent: Contracts, Drift Detection, and Authorization by Purpose"


def _goal_digest(goal: str) -> str:
    normalized = " ".join(goal.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def _summarize_contract(contract: IntentContract) -> dict[str, object]:
    return {
        "intent_id": contract.intent_id,
        "goal": contract.goal,
        "actor_role": contract.actor_role,
        "allowed_tools": sorted(contract.allowed_tools),
        "allowed_data": sorted(item.value for item in contract.allowed_data),
        "max_risk": contract.max_risk.value,
        "evidence_required": sorted(contract.evidence_required),
        "escalation_required_for": sorted(item.value for item in contract.escalation_required_for),
    }


def _evidence_gate(contract: IntentContract, supplied: frozenset[str]) -> PolicyDecision:
    missing = sorted(contract.evidence_required - supplied)
    if missing:
        return PolicyDecision(
            Decision.ESCALATE,
            "missing required intent evidence: " + ", ".join(missing),
            ("intent", "evidence_gate"),
        )
    return PolicyDecision(Decision.ALLOW, "required intent evidence present", ("intent", "evidence_gate"))


def _rewrite_or_escalate(contract: IntentContract, call: ToolCall) -> PolicyDecision:
    if call.tool == "send_customer_email" and call.side_effect == ActionRisk.EXTERNAL_COMMUNICATION:
        rewritten = ToolCall(
            tool="emit_trace",
            args={
                "event": "customer_notice_draft_blocked",
                "ticket": call.args.get("ticket", "unknown"),
                "redaction": "customer identifiers removed until communication purpose is approved",
            },
            data_class=DataClass.INTERNAL,
            side_effect=ActionRisk.READ,
            intent=contract.goal,
            context_refs=call.context_refs,
        )
        return PolicyDecision(
            Decision.REWRITE,
            "external communication rewritten to internal evidence until purpose-bound authorization exists",
            ("intent", "tool_rewrite", "least_privilege"),
            rewritten_call=rewritten,
        )

    if call.side_effect in contract.escalation_required_for:
        return PolicyDecision(
            Decision.ESCALATE,
            "contract requires human escalation for this tool-call purpose",
            ("intent", "tool_escalation"),
        )

    return PolicyDecision(
        Decision.ESCALATE,
        "tool call cannot be safely rewritten under the active intent contract",
        ("intent", "tool_escalation"),
    )


def _detect_stale_resume(checkpoint_state: dict[str, str], active_goal: str, active_contract: IntentContract) -> PolicyDecision:
    expected_goal = checkpoint_state.get("goal_digest")
    expected_contract = checkpoint_state.get("intent_id")
    active_goal_digest = _goal_digest(active_goal)
    if expected_goal != active_goal_digest or expected_contract != active_contract.intent_id:
        return PolicyDecision(
            Decision.ESCALATE,
            "resume checkpoint goal no longer matches the active purpose; reauthorization required",
            ("intent", "resume", "stale_goal"),
        )
    return PolicyDecision(Decision.ALLOW, "resume purpose still matches checkpoint", ("intent", "resume"))


def _purpose_bound_reauthorization(
    requested_goal: str,
    approval: dict[str, str],
    now: float,
) -> tuple[IntentContract | None, PolicyDecision]:
    if approval.get("purpose") != requested_goal:
        return None, PolicyDecision(
            Decision.DENY,
            "reauthorization approval is bound to a different purpose",
            ("intent", "reauthorization", "purpose_binding"),
        )

    contract = IntentContract(
        intent_id="intent-customer-notice",
        goal=requested_goal,
        actor_role="customer_comms_agent",
        allowed_tools=frozenset({"send_customer_email", "emit_trace"}),
        allowed_data=frozenset({DataClass.PUBLIC, DataClass.INTERNAL, DataClass.PII}),
        max_risk=ActionRisk.EXTERNAL_COMMUNICATION,
        evidence_required=frozenset({"approval_ticket", "message_template"}),
        expires_at=now + 600,
        escalation_required_for=frozenset(),
    )
    return contract, PolicyDecision(
        Decision.ALLOW,
        "new purpose-bound intent contract issued for approved customer notice",
        ("intent", "reauthorization", "purpose_binding"),
    )


def run() -> LabResult:
    now = time.time()
    harness = Harness()
    decisions: list[PolicyDecision] = []

    remediation_contract = IntentContract(
        intent_id="intent-remediate-billing-dependency",
        goal="remediate vulnerable dependency in billing-api",
        actor_role="remediation_agent",
        allowed_tools=frozenset({"read_ticket", "patch_repo", "emit_trace"}),
        allowed_data=frozenset({DataClass.PUBLIC, DataClass.INTERNAL}),
        max_risk=ActionRisk.REVERSIBLE_WRITE,
        evidence_required=frozenset({"ticket", "test_log"}),
        expires_at=now + 600,
        escalation_required_for=frozenset({ActionRisk.EXTERNAL_COMMUNICATION, ActionRisk.PRIVILEGED_OPERATION}),
    )

    decisions.append(_evidence_gate(remediation_contract, frozenset({"ticket", "test_log"})))

    read_ticket = ToolCall(
        tool="read_ticket",
        args={"ticket": "SEC-204", "service": "billing-api"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.READ,
        intent="remediate vulnerable dependency in billing-api",
        context_refs=("ticket:SEC-204",),
    )
    decisions.append(harness.intent.verify(remediation_contract, read_ticket))
    decisions.append(harness.gateway.check(read_ticket))

    patch_call = ToolCall(
        tool="patch_repo",
        args={"repo": "billing-api", "package": "safe-yaml", "target": "2.4.1"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.REVERSIBLE_WRITE,
        intent="remediate vulnerable dependency in billing-api",
        context_refs=("ticket:SEC-204", "test:dependency-regression"),
    )
    decisions.append(harness.intent.verify(remediation_contract, patch_call))
    decisions.append(harness.gateway.check(patch_call))

    drift_call = ToolCall(
        tool="patch_repo",
        args={"repo": "billing-api", "package": "ranking-model", "target": "latest"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.REVERSIBLE_WRITE,
        intent="optimize recommendation ranking while the repo is open",
        context_refs=("ticket:SEC-204",),
    )
    decisions.append(harness.intent.verify(remediation_contract, drift_call))

    deploy_call = ToolCall(
        tool="deploy_service",
        args={"service": "billing-api", "environment": "production"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.PRIVILEGED_OPERATION,
        intent="remediate vulnerable dependency in billing-api",
        context_refs=("ticket:SEC-204",),
    )
    decisions.append(harness.intent.verify(remediation_contract, deploy_call))

    customer_email = ToolCall(
        tool="send_customer_email",
        args={"ticket": "SEC-204", "customer": "learner@example.com", "template": "security_notice"},
        data_class=DataClass.PII,
        side_effect=ActionRisk.EXTERNAL_COMMUNICATION,
        intent="remediate vulnerable dependency in billing-api",
        context_refs=("ticket:SEC-204",),
    )
    decisions.append(harness.intent.verify(remediation_contract, customer_email))

    rewrite_decision = _rewrite_or_escalate(remediation_contract, customer_email)
    decisions.append(rewrite_decision)
    rewritten_call = rewrite_decision.rewritten_call
    if rewritten_call is not None:
        decisions.append(harness.intent.verify(remediation_contract, rewritten_call))
        decisions.append(harness.gateway.check(rewritten_call))

    checkpoint = harness.runtime.checkpoint(
        run_id="run-ch04-remediation",
        state={
            "intent_id": remediation_contract.intent_id,
            "goal_digest": _goal_digest(remediation_contract.goal),
            "last_completed_step": "patch_prepared",
        },
        policy_version="training-policy-v1",
        evidence_hash="evidence_remediation_001",
    )
    resumed_state = harness.runtime.resume_from(checkpoint.checkpoint_id)
    active_goal_after_resume = "notify affected customers about patched vulnerability"
    decisions.append(_detect_stale_resume(resumed_state, active_goal_after_resume, remediation_contract))

    mismatched_contract, mismatched_decision = _purpose_bound_reauthorization(
        active_goal_after_resume,
        {"approval_ticket": "APP-91", "purpose": "deploy billing-api to production"},
        now,
    )
    decisions.append(mismatched_decision)

    notice_contract, reauth_decision = _purpose_bound_reauthorization(
        active_goal_after_resume,
        {
            "approval_ticket": "APP-92",
            "purpose": active_goal_after_resume,
            "message_template": "security_notice",
        },
        now,
    )
    decisions.append(reauth_decision)

    notice_evidence_decision: PolicyDecision | None = None
    notice_verify_decision: PolicyDecision | None = None
    notice_gateway_decision: PolicyDecision | None = None
    if notice_contract is not None:
        notice_evidence_decision = _evidence_gate(notice_contract, frozenset({"approval_ticket", "message_template"}))
        decisions.append(notice_evidence_decision)
        notice_call = ToolCall(
            tool="send_customer_email",
            args={"ticket": "SEC-204", "template": "security_notice", "audience": "affected_customers"},
            data_class=DataClass.PII,
            side_effect=ActionRisk.EXTERNAL_COMMUNICATION,
            intent=active_goal_after_resume,
            context_refs=("approval:APP-92", "template:security_notice"),
        )
        notice_verify_decision = harness.intent.verify(notice_contract, notice_call)
        notice_gateway_decision = harness.gateway.check(notice_call)
        decisions.append(notice_verify_decision)
        decisions.append(notice_gateway_decision)

    counts = {decision.value: 0 for decision in Decision}
    for item in decisions:
        counts[item.decision.value] += 1

    checks = [
        counts[Decision.ALLOW.value] >= 8,
        counts[Decision.WARN.value] >= 1,
        counts[Decision.DENY.value] >= 3,
        counts[Decision.ESCALATE.value] >= 1,
        counts[Decision.REWRITE.value] >= 1,
        rewritten_call is not None,
        mismatched_contract is None,
        notice_contract is not None,
        notice_evidence_decision is not None,
        notice_evidence_decision.allowed,
        notice_verify_decision is not None,
        notice_verify_decision.allowed,
        notice_gateway_decision is not None,
        notice_gateway_decision.allowed,
    ]
    passed = all(checks)

    artifacts = {
        "contracts": [
            _summarize_contract(remediation_contract),
            _summarize_contract(notice_contract) if notice_contract is not None else None,
        ],
        "decision_counts": counts,
        "drift_detected": any(item.decision == Decision.WARN and "drifting" in item.reason for item in decisions),
        "purpose_denials": [
            item.reason
            for item in decisions
            if item.decision == Decision.DENY and ("purpose" in item.reason or "contract" in item.reason)
        ],
        "rewrite": {
            "from": customer_email.tool,
            "to": rewritten_call.tool if rewritten_call is not None else None,
            "rewritten_data_class": rewritten_call.data_class.value if rewritten_call is not None else None,
            "rewritten_side_effect": rewritten_call.side_effect.value if rewritten_call is not None else None,
        },
        "resume": {
            "checkpoint_id": checkpoint.checkpoint_id,
            "checkpoint_intent_id": resumed_state["intent_id"],
            "checkpoint_goal_digest": resumed_state["goal_digest"],
            "active_goal_digest": _goal_digest(active_goal_after_resume),
            "stale_goal_detected": True,
        },
        "reauthorization": {
            "rejected_wrong_purpose": mismatched_contract is None,
            "new_intent_id": notice_contract.intent_id if notice_contract is not None else None,
            "purpose": active_goal_after_resume,
            "authorized_tools": sorted(notice_contract.allowed_tools) if notice_contract is not None else [],
        },
        "controls": [
            "intent_contract",
            "evidence_gate",
            "drift_detection",
            "authorization_by_purpose",
            "tool_call_rewrite",
            "stale_goal_resume_check",
            "purpose_bound_reauthorization",
        ],
    }

    return LabResult(
        chapter="ch04",
        title=TITLE,
        passed=passed,
        score=score_from_checks(checks),
        summary=(
            "Intent contracts constrained tools, data, risk, evidence, resume state, and reauthorization so "
            "the agent could continue only under the currently approved purpose."
        ),
        decisions=decisions,
        artifacts=artifacts,
    )


if __name__ == "__main__":
    print(run().to_json())
