"""Chapter 2 scenario: autonomy gates for long-running agents.

The scenario is deterministic and dependency-free. It models the control-plane
shape of graduated autonomy: low-risk actions can run automatically, bounded
writes consume capability budget and register rollback hooks, risky actions
enter an approval queue, and non-waivable controls remain enforceable even when
an operator asks for a waiver.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from harnesslab.core import (
    ActionRisk,
    CapabilityBudget,
    DataClass,
    Decision,
    Harness,
    IntentContract,
    LabResult,
    PolicyDecision,
    ToolCall,
    ToolSpec,
    default_tools,
    score_from_checks,
    stable_id,
)


CHAPTER = "ch02"
TITLE = "Autonomy: Graduated Control and Human Oversight"
RUN_ID = "ch02-autonomy-run"


@dataclass(frozen=True)
class AutonomyRule:
    label: str
    mode: str
    approval_required: bool
    rollback_required: bool
    non_waivable: bool = False


@dataclass
class ApprovalRequest:
    request_id: str
    call: ToolCall
    required_evidence: tuple[str, ...]
    waiver_requested: bool = False
    status: str = "pending"
    reviewer: str | None = None
    reason: str = ""

    def to_artifact(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "tool": self.call.tool,
            "risk": self.call.side_effect.value,
            "required_evidence": list(self.required_evidence),
            "waiver_requested": self.waiver_requested,
            "status": self.status,
            "reviewer": self.reviewer,
            "reason": self.reason,
        }


@dataclass
class ApprovalQueue:
    requests: list[ApprovalRequest] = field(default_factory=list)

    def submit(self, call: ToolCall, required_evidence: tuple[str, ...], waiver_requested: bool = False) -> ApprovalRequest:
        request = ApprovalRequest(
            request_id=stable_id("approval", RUN_ID, call.tool, call.intent),
            call=call,
            required_evidence=required_evidence,
            waiver_requested=waiver_requested,
        )
        self.requests.append(request)
        return request

    def approve(self, request: ApprovalRequest, reviewer: str, evidence: frozenset[str]) -> PolicyDecision:
        missing = sorted(set(request.required_evidence) - set(evidence))
        if missing:
            request.status = "denied"
            request.reviewer = reviewer
            request.reason = "missing evidence: " + ", ".join(missing)
            return PolicyDecision(
                Decision.DENY,
                f"approval denied for {request.call.tool}; {request.reason}",
                ("approval_queue", "evidence_gate"),
            )
        request.status = "approved"
        request.reviewer = reviewer
        request.reason = "required evidence present"
        return PolicyDecision(
            Decision.ALLOW,
            f"approval granted for {request.call.tool} by {reviewer}",
            ("approval_queue", "human_oversight"),
        )


@dataclass
class RollbackHook:
    hook_id: str
    action: str
    checkpoint_id: str
    executed: bool = False

    def to_artifact(self) -> dict[str, Any]:
        return {
            "hook_id": self.hook_id,
            "action": self.action,
            "checkpoint_id": self.checkpoint_id,
            "executed": self.executed,
        }


class RollbackRegistry:
    def __init__(self) -> None:
        self._hooks: dict[str, RollbackHook] = {}

    def register(self, tool: str, checkpoint_id: str) -> RollbackHook:
        hook = RollbackHook(
            hook_id=stable_id("rollback", RUN_ID, tool, checkpoint_id),
            action=f"restore previous state after {tool}",
            checkpoint_id=checkpoint_id,
        )
        self._hooks[hook.hook_id] = hook
        return hook

    def execute(self, hook_id: str) -> PolicyDecision:
        hook = self._hooks[hook_id]
        hook.executed = True
        return PolicyDecision(
            Decision.ALLOW,
            f"rollback hook executed: {hook.action}",
            ("rollback", "reversible_action"),
        )

    def artifacts(self) -> list[dict[str, Any]]:
        return [hook.to_artifact() for hook in self._hooks.values()]


AUTONOMY_RULES: dict[ActionRisk, AutonomyRule] = {
    ActionRisk.READ: AutonomyRule("observe", "autonomous", approval_required=False, rollback_required=False),
    ActionRisk.REVERSIBLE_WRITE: AutonomyRule(
        "bounded-write",
        "autonomous-with-budget",
        approval_required=False,
        rollback_required=True,
    ),
    ActionRisk.EXTERNAL_COMMUNICATION: AutonomyRule(
        "supervised-communication",
        "approval-queue",
        approval_required=True,
        rollback_required=False,
    ),
    ActionRisk.IRREVERSIBLE_WRITE: AutonomyRule(
        "irreversible-change",
        "approval-queue",
        approval_required=True,
        rollback_required=False,
    ),
    ActionRisk.PRIVILEGED_OPERATION: AutonomyRule(
        "privileged-operation",
        "approval-queue",
        approval_required=True,
        rollback_required=False,
    ),
}


def _contract(
    *,
    allowed_tools: frozenset[str],
    allowed_data: frozenset[DataClass],
    max_risk: ActionRisk,
    evidence_required: frozenset[str],
    expires_at: float | None = None,
    escalation_required_for: frozenset[ActionRisk] = frozenset(),
) -> IntentContract:
    return IntentContract(
        intent_id=stable_id("intent", RUN_ID, ",".join(sorted(allowed_tools))),
        goal="triage autonomy incident",
        actor_role="autonomy_controller",
        allowed_tools=allowed_tools,
        allowed_data=allowed_data,
        max_risk=max_risk,
        evidence_required=evidence_required,
        expires_at=expires_at if expires_at is not None else time.time() + 600,
        escalation_required_for=escalation_required_for,
    )


def _decision_for_gate(call: ToolCall, rule: AutonomyRule) -> PolicyDecision:
    if rule.approval_required:
        return PolicyDecision(
            Decision.ESCALATE,
            f"{call.side_effect.value} enters {rule.mode}",
            ("autonomy_gate", rule.label),
        )
    return PolicyDecision(
        Decision.ALLOW,
        f"{call.side_effect.value} allowed at {rule.mode}",
        ("autonomy_gate", rule.label),
    )


def _non_waivable_secret_block(call: ToolCall, waiver_requested: bool) -> PolicyDecision | None:
    if waiver_requested and call.data_class == DataClass.SECRET:
        return PolicyDecision(
            Decision.DENY,
            "non-waivable control blocked secret access despite waiver request",
            ("non_waivable", "secret_boundary", "approval_queue"),
        )
    return None


def _add_chapter_tools(harness: Harness) -> None:
    tools = default_tools() + [
        ToolSpec(
            "delete_customer_record",
            ActionRisk.IRREVERSIBLE_WRITE,
            frozenset({DataClass.PII}),
            False,
            "Delete a customer record after retention review.",
        )
    ]
    harness.gateway.tools = {tool.name: tool for tool in tools}


def run() -> LabResult:
    harness = Harness()
    _add_chapter_tools(harness)
    approvals = ApprovalQueue()
    rollback_registry = RollbackRegistry()
    decisions: list[PolicyDecision] = []
    timeline: list[dict[str, Any]] = []

    budget = CapabilityBudget(
        tool_limits={"patch_repo": 1, "send_customer_email": 1, "deploy_service": 1},
        risk_limits={
            ActionRisk.REVERSIBLE_WRITE: 1,
            ActionRisk.EXTERNAL_COMMUNICATION: 1,
            ActionRisk.PRIVILEGED_OPERATION: 1,
        },
        approvals_required=frozenset({ActionRisk.EXTERNAL_COMMUNICATION, ActionRisk.PRIVILEGED_OPERATION}),
    )

    read_call = ToolCall(
        tool="read_ticket",
        args={"ticket": "AUTO-100", "fields": ["title", "severity", "owner"]},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.READ,
        intent="triage autonomy incident from queue",
    )
    base_contract = _contract(
        allowed_tools=frozenset({"read_ticket", "patch_repo", "send_customer_email"}),
        allowed_data=frozenset({DataClass.INTERNAL, DataClass.PUBLIC}),
        max_risk=ActionRisk.EXTERNAL_COMMUNICATION,
        evidence_required=frozenset({"ticket", "policy"}),
        escalation_required_for=frozenset({ActionRisk.EXTERNAL_COMMUNICATION}),
    )

    read_gate = _decision_for_gate(read_call, AUTONOMY_RULES[read_call.side_effect])
    decisions.append(read_gate)
    for decision in (harness.gateway.check(read_call), harness.intent.verify(base_contract, read_call), budget.check(read_call)):
        decisions.append(decision)
    if decisions[-1].allowed:
        budget.spend(read_call)
    timeline.append({"step": "observe", "tool": read_call.tool, "outcome": "allowed"})

    patch_call = ToolCall(
        tool="patch_repo",
        args={"branch": "training/autonomy-budget", "change": "add bounded retry limit"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.REVERSIBLE_WRITE,
        intent="triage autonomy incident with bounded repository patch",
    )
    patch_gate = _decision_for_gate(patch_call, AUTONOMY_RULES[patch_call.side_effect])
    decisions.append(patch_gate)
    for decision in (harness.gateway.check(patch_call), harness.intent.verify(base_contract, patch_call), budget.check(patch_call)):
        decisions.append(decision)
    if decisions[-1].allowed:
        budget.spend(patch_call)
        checkpoint = harness.runtime.checkpoint(
            RUN_ID,
            {"branch": "main", "feature_flag": "autonomy_retry_limit=old"},
            "training-policy-v1",
            "evidence-hash-ch02-patch",
        )
        rollback_registry.register(patch_call.tool, checkpoint.checkpoint_id)
    timeline.append({"step": "bounded_write", "tool": patch_call.tool, "outcome": "allowed_with_rollback"})

    second_patch = ToolCall(
        tool="patch_repo",
        args={"branch": "training/autonomy-budget", "change": "change production throttle again"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.REVERSIBLE_WRITE,
        intent="triage autonomy incident with second repository patch",
    )
    decisions.append(_decision_for_gate(second_patch, AUTONOMY_RULES[second_patch.side_effect]))
    budget_denial = budget.check(second_patch)
    decisions.append(budget_denial)
    timeline.append({"step": "capability_budget", "tool": second_patch.tool, "outcome": budget_denial.decision.value})

    email_call = ToolCall(
        tool="send_customer_email",
        args={"template": "incident-update", "audience": "affected beta testers"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.EXTERNAL_COMMUNICATION,
        intent="triage autonomy incident with customer communication",
    )
    email_gate = _decision_for_gate(email_call, AUTONOMY_RULES[email_call.side_effect])
    decisions.append(email_gate)
    for decision in (harness.gateway.check(email_call), harness.intent.verify(base_contract, email_call), budget.check(email_call)):
        decisions.append(decision)
    email_request = approvals.submit(email_call, ("ticket", "message_preview", "owner_ack"))
    email_approval = approvals.approve(email_request, "human:incident-commander", frozenset({"ticket", "message_preview", "owner_ack"}))
    decisions.append(email_approval)
    if email_approval.allowed:
        budget.spend(email_call)
    timeline.append({"step": "approval_queue", "tool": email_call.tool, "outcome": email_request.status})

    irreversible_call = ToolCall(
        tool="delete_customer_record",
        args={"customer_id": "cust-training-009", "reason": "agent suggested cleanup"},
        data_class=DataClass.PII,
        side_effect=ActionRisk.IRREVERSIBLE_WRITE,
        intent="triage autonomy incident by deleting stale customer record",
    )
    irreversible_contract = _contract(
        allowed_tools=frozenset({"delete_customer_record"}),
        allowed_data=frozenset({DataClass.PII}),
        max_risk=ActionRisk.IRREVERSIBLE_WRITE,
        evidence_required=frozenset({"retention_ticket", "two_person_review", "export_receipt"}),
        escalation_required_for=frozenset({ActionRisk.IRREVERSIBLE_WRITE}),
    )
    decisions.append(_decision_for_gate(irreversible_call, AUTONOMY_RULES[irreversible_call.side_effect]))
    decisions.append(harness.gateway.check(irreversible_call))
    decisions.append(harness.intent.verify(irreversible_contract, irreversible_call))
    irreversible_request = approvals.submit(
        irreversible_call,
        ("retention_ticket", "two_person_review", "export_receipt"),
    )
    irreversible_denial = approvals.approve(irreversible_request, "human:privacy-reviewer", frozenset({"retention_ticket"}))
    decisions.append(irreversible_denial)
    timeline.append({"step": "irreversible_action", "tool": irreversible_call.tool, "outcome": irreversible_request.status})

    secret_call = ToolCall(
        tool="query_vault",
        args={"path": "prod/payments/api_key"},
        data_class=DataClass.SECRET,
        side_effect=ActionRisk.PRIVILEGED_OPERATION,
        intent="triage autonomy incident by fetching production secret",
    )
    secret_request = approvals.submit(secret_call, ("break_glass_record",), waiver_requested=True)
    secret_block = _non_waivable_secret_block(secret_call, waiver_requested=True)
    if secret_block is not None:
        secret_request.status = "denied"
        secret_request.reviewer = "system:non-waivable-control"
        secret_request.reason = "secret access requires a separate break-glass authority"
        decisions.append(secret_block)
    timeline.append({"step": "non_waivable", "tool": secret_call.tool, "outcome": "denied"})

    deploy_call = ToolCall(
        tool="deploy_service",
        args={"service": "autonomy-sandbox", "environment": "training"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.PRIVILEGED_OPERATION,
        intent="triage autonomy incident with controlled deployment",
    )
    expired_contract = _contract(
        allowed_tools=frozenset({"deploy_service"}),
        allowed_data=frozenset({DataClass.INTERNAL}),
        max_risk=ActionRisk.PRIVILEGED_OPERATION,
        evidence_required=frozenset({"test_log", "change_ticket"}),
        expires_at=0,
        escalation_required_for=frozenset({ActionRisk.PRIVILEGED_OPERATION}),
    )
    expired_decision = harness.intent.verify(expired_contract, deploy_call)
    decisions.append(expired_decision)
    renewed_contract = _contract(
        allowed_tools=frozenset({"deploy_service"}),
        allowed_data=frozenset({DataClass.INTERNAL}),
        max_risk=ActionRisk.PRIVILEGED_OPERATION,
        evidence_required=frozenset({"test_log", "change_ticket"}),
        escalation_required_for=frozenset({ActionRisk.PRIVILEGED_OPERATION}),
    )
    decisions.append(_decision_for_gate(deploy_call, AUTONOMY_RULES[deploy_call.side_effect]))
    for decision in (harness.gateway.check(deploy_call), harness.intent.verify(renewed_contract, deploy_call), budget.check(deploy_call)):
        decisions.append(decision)
    deploy_request = approvals.submit(deploy_call, ("test_log", "change_ticket", "lease_renewal"))
    deploy_approval = approvals.approve(deploy_request, "human:release-manager", frozenset({"test_log", "change_ticket", "lease_renewal"}))
    decisions.append(deploy_approval)
    if deploy_approval.allowed:
        budget.spend(deploy_call)
    timeline.append({"step": "lease_renewal", "tool": deploy_call.tool, "outcome": deploy_request.status})

    rollback_hooks = rollback_registry.artifacts()
    rollback_decision = rollback_registry.execute(rollback_hooks[0]["hook_id"])
    decisions.append(rollback_decision)
    rollback_hooks = rollback_registry.artifacts()
    timeline.append({"step": "rollback", "tool": patch_call.tool, "outcome": "executed"})

    control_checks = {
        "read_action_autonomous": read_gate.allowed,
        "reversible_write_registered_rollback": bool(rollback_hooks) and rollback_hooks[0]["executed"],
        "capability_budget_blocks_second_patch": budget_denial.decision == Decision.DENY,
        "external_communication_approved_by_queue": email_request.status == "approved",
        "irreversible_action_denied_without_full_evidence": irreversible_request.status == "denied",
        "non_waivable_secret_boundary_enforced": secret_block is not None and secret_block.decision == Decision.DENY,
        "expired_long_run_lease_denied": expired_decision.decision == Decision.DENY,
        "renewed_privileged_action_approved": deploy_request.status == "approved",
    }

    artifacts: dict[str, Any] = {
        "autonomy_gates": {
            risk.value: {
                "label": rule.label,
                "mode": rule.mode,
                "approval_required": rule.approval_required,
                "rollback_required": rule.rollback_required,
            }
            for risk, rule in AUTONOMY_RULES.items()
        },
        "timeline": timeline,
        "approval_queue": [request.to_artifact() for request in approvals.requests],
        "capability_budgets": {
            "tool_limits": dict(budget.tool_limits),
            "spent_tools": dict(budget.spent_tools),
            "risk_limits": {risk.value: limit for risk, limit in budget.risk_limits.items()},
            "spent_risks": {risk.value: spent for risk, spent in budget.spent_risks.items()},
        },
        "rollback_hooks": rollback_hooks,
        "lease_events": [
            "privileged action denied after original lease expired",
            "lease renewed with same tool, data, risk, and evidence scope",
            "renewed lease still required approval before deployment",
        ],
        "control_checks": control_checks,
    }

    passed = all(control_checks.values())
    return LabResult(
        chapter=CHAPTER,
        title=TITLE,
        passed=passed,
        score=score_from_checks(control_checks.values()),
        summary=(
            "Graduated autonomy allowed low-risk work, queued supervised actions, "
            "blocked budget exhaustion and non-waivable secret access, renewed an "
            "expired long-running lease, and executed rollback for a reversible write."
        ),
        decisions=decisions,
        artifacts=artifacts,
    )
