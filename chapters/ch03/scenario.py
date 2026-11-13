from __future__ import annotations

import time

from harnesslab.core import (
    ActionRisk,
    AgentIdentity,
    Credential,
    DataClass,
    Decision,
    Harness,
    IntentContract,
    LabResult,
    PolicyDecision,
    TaskIdentity,
    ToolCall,
    score_from_checks,
    stable_id,
)


TITLE = "Identity: Per-Agent Identity and Delegation Chains"


def _task(run_id: str, name: str, actor: AgentIdentity, now: float, ttl_seconds: int = 900) -> TaskIdentity:
    return TaskIdentity(
        run_id=run_id,
        task_id=stable_id("task", run_id, name, actor.agent_id),
        actor=actor,
        created_at=now,
        expires_at=now + ttl_seconds,
    )


def _subject(task: TaskIdentity, generation: int = 1) -> str:
    return f"{task.actor.agent_id}:{task.task_id}:g{generation}"


def _agents_are_distinct(agents: tuple[AgentIdentity, ...]) -> PolicyDecision:
    agent_ids = {agent.agent_id for agent in agents}
    roles = {agent.role for agent in agents}
    delegated = all(agent.parent_id == "agent-planner" for agent in agents if agent.agent_id != "agent-planner")
    if len(agent_ids) == len(agents) and len(roles) == len(agents) and delegated:
        return PolicyDecision(Decision.ALLOW, "distinct per-agent identities and parent links established", ("identity", "per_agent"))
    return PolicyDecision(Decision.DENY, "agent identities are not uniquely attributable", ("identity", "per_agent"))


def _tasks_are_distinct(tasks: tuple[TaskIdentity, ...]) -> PolicyDecision:
    task_ids = {task.task_id for task in tasks}
    subjects = {_subject(task) for task in tasks}
    actors = {task.actor.agent_id for task in tasks}
    if len(task_ids) == len(tasks) and len(subjects) == len(tasks) and len(actors) == len(tasks):
        return PolicyDecision(Decision.ALLOW, "each task has a separate actor-bound task identity", ("identity", "per_task"))
    return PolicyDecision(Decision.DENY, "task identities collapsed across work items", ("identity", "per_task"))


def _delegation_chain_matches(credential: Credential, expected: tuple[str, ...]) -> PolicyDecision:
    if credential.delegation_chain == expected:
        chain = " -> ".join(expected)
        return PolicyDecision(Decision.ALLOW, f"delegation chain preserved: {chain}", ("identity", "delegation_chain"))
    return PolicyDecision(Decision.DENY, "delegation chain did not match the approved handoff", ("identity", "delegation_chain"))


def _resource_scope(task: TaskIdentity, call: ToolCall, allowed_resources: frozenset[str]) -> PolicyDecision:
    resource = str(call.args.get("resource", ""))
    if resource in allowed_resources:
        return PolicyDecision(Decision.ALLOW, f"{resource} is scoped to {task.task_id}", ("identity", "resource_scope"))
    return PolicyDecision(Decision.DENY, f"{resource} is outside resource scope for {task.task_id}", ("identity", "resource_scope"))


def _count(decisions: list[PolicyDecision], decision: Decision) -> int:
    return sum(1 for item in decisions if item.decision == decision)


def run() -> LabResult:
    harness = Harness()
    now = time.time()
    run_id = stable_id("run", "ch03", "identity-control-plane")
    decisions: list[PolicyDecision] = []

    planner = AgentIdentity("agent-planner", "incident_planner", tenant="acme")
    reader = AgentIdentity("agent-reader", "ticket_reader", tenant="acme", parent_id=planner.agent_id)
    patcher = AgentIdentity("agent-patcher", "repo_remediator", tenant="acme", parent_id=planner.agent_id)
    auditor = AgentIdentity("agent-auditor", "security_auditor", tenant="acme", parent_id=planner.agent_id)
    agents = (planner, reader, patcher, auditor)
    decisions.append(_agents_are_distinct(agents))

    read_task = _task(run_id, "read-customer-ticket", reader, now)
    patch_task = _task(run_id, "prepare-repository-patch", patcher, now)
    audit_task = _task(run_id, "audit-evidence", auditor, now)
    tasks = (read_task, patch_task, audit_task)
    decisions.append(_tasks_are_distinct(tasks))

    read_subject = _subject(read_task)
    read_credential = harness.broker.issue(
        subject=read_subject,
        audience="internal-ticketing",
        ttl_seconds=60,
        delegation_chain=(planner.agent_id, reader.agent_id),
    )
    decisions.append(harness.broker.verify(read_credential, "internal-ticketing"))
    decisions.append(harness.broker.verify(read_credential, "internal-repo"))

    expired_subject = f"{audit_task.actor.agent_id}:{audit_task.task_id}:expired"
    expired_credential = harness.broker.issue(
        subject=expired_subject,
        audience="training-console",
        ttl_seconds=1,
        delegation_chain=(planner.agent_id, auditor.agent_id),
    )
    expired_credential.expires_at = time.time() - 1
    decisions.append(harness.broker.verify(expired_credential, "training-console"))

    patch_subject = _subject(patch_task)
    patch_credential = harness.broker.issue(
        subject=patch_subject,
        audience="internal-repo",
        ttl_seconds=120,
        delegation_chain=(planner.agent_id, patcher.agent_id),
    )
    decisions.append(harness.broker.verify(patch_credential, "internal-repo"))
    decisions.append(_delegation_chain_matches(patch_credential, (planner.agent_id, patcher.agent_id)))

    revoked_patch_credentials = harness.broker.revoke_subject(patch_subject)
    revocation_decision = Decision.ALLOW if revoked_patch_credentials == 1 else Decision.DENY
    decisions.append(
        PolicyDecision(
            revocation_decision,
            f"revoked {revoked_patch_credentials} credential for {patch_subject}",
            ("identity", "revocation"),
        )
    )
    decisions.append(harness.broker.verify(patch_credential, "internal-repo"))

    runtime_subject_v1 = _subject(audit_task, generation=1)
    runtime_credential_v1 = harness.broker.issue(
        subject=runtime_subject_v1,
        audience="training-console",
        ttl_seconds=180,
        delegation_chain=(planner.agent_id, patcher.agent_id, auditor.agent_id),
    )
    decisions.append(harness.broker.verify(runtime_credential_v1, "training-console"))
    decisions.append(harness.runtime.pause(run_id, "rotate task credentials before continuing long-running audit"))
    checkpoint = harness.runtime.checkpoint(
        run_id,
        {"task_id": audit_task.task_id, "credential_generation": 1},
        "identity-policy-v1",
        "identity-evidence-v1",
    )
    revoked_runtime_credentials = harness.broker.revoke_subject(runtime_subject_v1)
    decisions.append(
        PolicyDecision(
            Decision.ALLOW if revoked_runtime_credentials == 1 else Decision.DENY,
            f"revoked {revoked_runtime_credentials} paused-run credential before resume",
            ("identity", "revocation", "runtime_steering"),
        )
    )
    decisions.append(harness.broker.verify(runtime_credential_v1, "training-console"))
    resumed_state = harness.runtime.resume_from(checkpoint.checkpoint_id)
    runtime_credential_v2 = harness.broker.issue(
        subject=_subject(audit_task, generation=2),
        audience="training-console",
        ttl_seconds=180,
        delegation_chain=(planner.agent_id, patcher.agent_id, auditor.agent_id),
    )
    decisions.append(harness.broker.verify(runtime_credential_v2, "training-console"))
    resumed_with_rotation = resumed_state.get("credential_generation") == 1 and run_id not in harness.runtime.paused
    decisions.append(
        PolicyDecision(
            Decision.ALLOW if resumed_with_rotation else Decision.DENY,
            "resumed from checkpoint with a fresh credential generation",
            ("runtime_steering", "credential_rotation"),
        )
    )

    read_contract = IntentContract(
        intent_id=stable_id("intent", read_task.task_id, "ticket-read"),
        goal="investigate customer ticket",
        actor_role=reader.role,
        allowed_tools=frozenset({"read_ticket", "emit_trace"}),
        allowed_data=frozenset({DataClass.INTERNAL, DataClass.PII}),
        max_risk=ActionRisk.READ,
        evidence_required=frozenset({"ticket_id", "task_id"}),
        expires_at=now + 600,
    )
    patch_contract = IntentContract(
        intent_id=stable_id("intent", patch_task.task_id, "repo-patch"),
        goal="patch repository",
        actor_role=patcher.role,
        allowed_tools=frozenset({"patch_repo", "emit_trace"}),
        allowed_data=frozenset({DataClass.PUBLIC, DataClass.INTERNAL}),
        max_risk=ActionRisk.REVERSIBLE_WRITE,
        evidence_required=frozenset({"pull_request", "task_id"}),
        expires_at=now + 600,
    )
    deployment_review_contract = IntentContract(
        intent_id=stable_id("intent", patch_task.task_id, "deployment-review"),
        goal="patch repository",
        actor_role=patcher.role,
        allowed_tools=frozenset({"deploy_service"}),
        allowed_data=frozenset({DataClass.INTERNAL}),
        max_risk=ActionRisk.REVERSIBLE_WRITE,
        evidence_required=frozenset({"human_approval", "task_id"}),
        expires_at=now + 600,
    )

    resource_scopes = {
        read_task.task_id: frozenset({"ticket:acme/SEC-203"}),
        patch_task.task_id: frozenset({"repo:acme/checkout-service"}),
        audit_task.task_id: frozenset({"trace:acme/ch03-run"}),
    }

    read_call = ToolCall(
        tool="read_ticket",
        args={"resource": "ticket:acme/SEC-203", "ticket": "SEC-203"},
        data_class=DataClass.PII,
        side_effect=ActionRisk.READ,
        intent="investigate customer ticket before patching",
    )
    decisions.append(harness.intent.verify(read_contract, read_call))
    decisions.append(harness.gateway.check(read_call))
    decisions.append(_resource_scope(read_task, read_call, resource_scopes[read_task.task_id]))

    cross_tenant_call = ToolCall(
        tool="read_ticket",
        args={"resource": "ticket:globex/SEC-999", "ticket": "SEC-999"},
        data_class=DataClass.PII,
        side_effect=ActionRisk.READ,
        intent="investigate customer ticket before patching",
    )
    decisions.append(_resource_scope(read_task, cross_tenant_call, resource_scopes[read_task.task_id]))

    vault_call = ToolCall(
        tool="query_vault",
        args={"resource": "vault:acme/payment-api", "path": "prod/payment/api_key"},
        data_class=DataClass.SECRET,
        side_effect=ActionRisk.PRIVILEGED_OPERATION,
        intent="investigate customer ticket by reading secrets",
    )
    decisions.append(harness.intent.verify(read_contract, vault_call))

    patch_call = ToolCall(
        tool="patch_repo",
        args={"resource": "repo:acme/checkout-service", "path": "auth/session.py"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.REVERSIBLE_WRITE,
        intent="patch repository with approved identity fix",
    )
    decisions.append(harness.intent.verify(patch_contract, patch_call))
    decisions.append(harness.gateway.check(patch_call))
    decisions.append(_resource_scope(patch_task, patch_call, resource_scopes[patch_task.task_id]))

    pii_patch_call = ToolCall(
        tool="patch_repo",
        args={"resource": "repo:acme/customer-export", "path": "exports/customers.csv"},
        data_class=DataClass.PII,
        side_effect=ActionRisk.REVERSIBLE_WRITE,
        intent="patch repository with approved identity fix",
    )
    decisions.append(harness.intent.verify(patch_contract, pii_patch_call))
    decisions.append(harness.gateway.check(pii_patch_call))
    decisions.append(_resource_scope(patch_task, pii_patch_call, resource_scopes[patch_task.task_id]))

    deploy_call = ToolCall(
        tool="deploy_service",
        args={"resource": "repo:acme/checkout-service", "service": "checkout"},
        data_class=DataClass.INTERNAL,
        side_effect=ActionRisk.PRIVILEGED_OPERATION,
        intent="patch repository by deploying immediately",
    )
    decisions.append(harness.intent.verify(deployment_review_contract, deploy_call))

    allowed = _count(decisions, Decision.ALLOW)
    denied = _count(decisions, Decision.DENY)
    warned = _count(decisions, Decision.WARN)
    escalated = _count(decisions, Decision.ESCALATE)
    controls = {control for item in decisions for control in item.controls}
    required_controls = {
        "per_agent",
        "per_task",
        "audience_binding",
        "short_lived_credential",
        "delegation_chain",
        "revocation",
        "credential_rotation",
        "tool_scope",
        "data_scope",
        "resource_scope",
        "risk_boundary",
    }
    checks = [
        allowed >= 15,
        denied >= 5,
        warned >= 1,
        escalated >= 1,
        required_controls.issubset(controls),
    ]
    passed = all(checks)

    return LabResult(
        chapter="ch03",
        title=TITLE,
        passed=passed,
        score=score_from_checks(checks),
        summary=(
            "Per-agent and per-task identities issued short-lived audience-bound credentials, "
            "preserved delegation chains, revoked stale grants, rotated credentials across pause/resume, "
            "and enforced least-privilege tool, data, and resource scope."
        ),
        decisions=decisions,
        artifacts={
            "run_id": run_id,
            "agents": [
                {"agent_id": agent.agent_id, "role": agent.role, "tenant": agent.tenant, "parent_id": agent.parent_id}
                for agent in agents
            ],
            "tasks": [
                {"task_id": task.task_id, "actor": task.actor.agent_id, "subject": _subject(task)}
                for task in tasks
            ],
            "credential_audiences": {
                "read_task": "internal-ticketing",
                "patch_task": "internal-repo",
                "audit_task": "training-console",
            },
            "delegation_chains": {
                "read_task": list(read_credential.delegation_chain),
                "patch_task": list(patch_credential.delegation_chain),
                "audit_task": list(runtime_credential_v2.delegation_chain),
            },
            "revoked_subjects": [patch_subject, runtime_subject_v1],
            "checkpoint": {
                "checkpoint_id": checkpoint.checkpoint_id,
                "policy_version": checkpoint.policy_version,
                "state": dict(checkpoint.state),
            },
            "least_privilege": {
                "allowed_tools": {
                    read_task.task_id: sorted(read_contract.allowed_tools),
                    patch_task.task_id: sorted(patch_contract.allowed_tools),
                    "deployment_review": sorted(deployment_review_contract.allowed_tools),
                },
                "resource_scopes": {key: sorted(value) for key, value in resource_scopes.items()},
                "blocked_examples": [
                    "credential:wrong-audience",
                    "credential:expired",
                    "credential:revoked",
                    "tool:query-vault",
                    "resource:cross-tenant-ticket",
                    "data:pii-repo-patch",
                    "risk:privileged-deploy",
                ],
            },
            "decision_counts": {
                "allow": allowed,
                "deny": denied,
                "warn": warned,
                "escalate": escalated,
            },
            "controls": sorted(controls),
        },
    )


if __name__ == "__main__":
    print(run().to_json())
