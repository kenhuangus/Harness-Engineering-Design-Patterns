"""Core secure-harness primitives used by all Harness-Engineering-Design-Patterns chapters.

The implementation is intentionally deterministic and dependency-free. It is
not a replacement for production security infrastructure, but it models the
control-plane shapes students should recognize in production systems: identity,
intent, policy, provenance, memory, traces, steering, fleet controls, and data
governance.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"
    REWRITE = "rewrite"
    WARN = "warn"


class TrustTier(str, Enum):
    SYSTEM = "system"
    TENANT = "tenant"
    TRUSTED_TOOL = "trusted_tool"
    USER = "user"
    EXTERNAL = "external"
    QUARANTINED = "quarantined"


class DataClass(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    SECRET = "secret"
    REGULATED = "regulated"


class ActionRisk(str, Enum):
    READ = "read"
    REVERSIBLE_WRITE = "reversible_write"
    IRREVERSIBLE_WRITE = "irreversible_write"
    EXTERNAL_COMMUNICATION = "external_communication"
    PRIVILEGED_OPERATION = "privileged_operation"


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    role: str
    tenant: str = "training"
    parent_id: str | None = None


@dataclass(frozen=True)
class TaskIdentity:
    run_id: str
    task_id: str
    actor: AgentIdentity
    created_at: float
    expires_at: float

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass
class Credential:
    token: str
    subject: str
    audience: str
    issued_at: float
    expires_at: float
    delegation_chain: tuple[str, ...]
    revoked: bool = False

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk: ActionRisk
    data_classes: frozenset[DataClass]
    reversible: bool
    description: str


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, Any]
    data_class: DataClass
    side_effect: ActionRisk
    intent: str
    context_refs: tuple[str, ...] = ()


@dataclass
class PolicyDecision:
    decision: Decision
    reason: str
    controls: tuple[str, ...] = ()
    rewritten_call: ToolCall | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW


@dataclass
class IntentContract:
    intent_id: str
    goal: str
    actor_role: str
    allowed_tools: frozenset[str]
    allowed_data: frozenset[DataClass]
    max_risk: ActionRisk
    evidence_required: frozenset[str]
    expires_at: float
    escalation_required_for: frozenset[ActionRisk] = field(default_factory=frozenset)

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at


@dataclass
class CapabilityBudget:
    tool_limits: dict[str, int]
    risk_limits: dict[ActionRisk, int]
    approvals_required: frozenset[ActionRisk]
    spent_tools: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    spent_risks: dict[ActionRisk, int] = field(default_factory=lambda: defaultdict(int))

    def check(self, call: ToolCall) -> PolicyDecision:
        tool_spent = self.spent_tools[call.tool]
        tool_limit = self.tool_limits.get(call.tool)
        if tool_limit is not None and tool_spent >= tool_limit:
            return PolicyDecision(Decision.DENY, f"tool budget exhausted for {call.tool}", ("capability_budget",))

        risk_spent = self.spent_risks[call.side_effect]
        risk_limit = self.risk_limits.get(call.side_effect)
        if risk_limit is not None and risk_spent >= risk_limit:
            return PolicyDecision(Decision.DENY, f"risk budget exhausted for {call.side_effect.value}", ("capability_budget",))

        if call.side_effect in self.approvals_required:
            return PolicyDecision(Decision.ESCALATE, f"{call.side_effect.value} requires approval", ("human_oversight",))

        return PolicyDecision(Decision.ALLOW, "budget available", ("capability_budget",))

    def spend(self, call: ToolCall) -> None:
        self.spent_tools[call.tool] += 1
        self.spent_risks[call.side_effect] += 1


@dataclass
class ContextItem:
    context_id: str
    source: str
    text: str
    trust_tier: TrustTier
    data_class: DataClass
    created_at: float
    provenance: str
    quarantined: bool = False
    findings: tuple[str, ...] = ()


@dataclass
class MemoryRecord:
    record_id: str
    key: str
    value: str
    tenant: str
    data_class: DataClass
    trust_tier: TrustTier
    source_hash: str
    policy_version: str
    created_at: float
    ttl_seconds: int
    deleted: bool = False
    tombstone_reason: str | None = None

    @property
    def expired(self) -> bool:
        return time.time() >= self.created_at + self.ttl_seconds


@dataclass
class TraceSpan:
    span_id: str
    name: str
    started_at: float
    ended_at: float | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def finish(self) -> None:
        self.ended_at = time.time()


@dataclass
class EvidenceEnvelope:
    run_id: str
    actor: str
    policy_version: str
    spans: list[TraceSpan]
    artifact_hashes: dict[str, str]
    redactions: list[str]
    created_at: float

    def tamper_evident_hash(self) -> str:
        payload = json.dumps(
            {
                "run_id": self.run_id,
                "actor": self.actor,
                "policy_version": self.policy_version,
                "spans": [span.__dict__ for span in self.spans],
                "artifact_hashes": self.artifact_hashes,
                "redactions": self.redactions,
                "created_at": round(self.created_at, 6),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Checkpoint:
    checkpoint_id: str
    run_id: str
    state: dict[str, Any]
    policy_version: str
    created_at: float
    evidence_hash: str


@dataclass
class LabResult:
    chapter: str
    title: str
    passed: bool
    score: float
    summary: str
    decisions: list[PolicyDecision] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chapter": self.chapter,
            "title": self.title,
            "passed": self.passed,
            "score": self.score,
            "summary": self.summary,
            "decisions": [
                {
                    "decision": item.decision.value,
                    "reason": item.reason,
                    "controls": list(item.controls),
                    "rewritten_call": item.rewritten_call.tool if item.rewritten_call else None,
                }
                for item in self.decisions
            ],
            "artifacts": self.artifacts,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class CredentialBroker:
    def __init__(self, secret: bytes = b"harnesslab-training-secret") -> None:
        self._secret = secret
        self._issued: dict[str, Credential] = {}

    def issue(self, subject: str, audience: str, ttl_seconds: int, delegation_chain: Iterable[str]) -> Credential:
        issued_at = time.time()
        expires_at = issued_at + ttl_seconds
        nonce = str(uuid.uuid4())
        message = f"{subject}|{audience}|{expires_at:.6f}|{nonce}".encode("utf-8")
        token = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        credential = Credential(token, subject, audience, issued_at, expires_at, tuple(delegation_chain))
        self._issued[token] = credential
        return credential

    def verify(self, credential: Credential, audience: str) -> PolicyDecision:
        known = self._issued.get(credential.token)
        if known is None:
            return PolicyDecision(Decision.DENY, "unknown credential", ("identity",))
        if known.revoked:
            return PolicyDecision(Decision.DENY, "credential revoked", ("identity", "revocation"))
        if known.expired:
            return PolicyDecision(Decision.DENY, "credential expired", ("identity", "short_lived_credential"))
        if not hmac.compare_digest(known.audience, audience):
            return PolicyDecision(Decision.DENY, "credential audience mismatch", ("identity", "audience_binding"))
        return PolicyDecision(Decision.ALLOW, "credential valid", ("identity", "delegation_chain"))

    def revoke_subject(self, subject: str) -> int:
        count = 0
        for credential in self._issued.values():
            if credential.subject == subject and not credential.revoked:
                credential.revoked = True
                count += 1
        return count


class IntentVerifier:
    risk_order = {
        ActionRisk.READ: 0,
        ActionRisk.REVERSIBLE_WRITE: 1,
        ActionRisk.EXTERNAL_COMMUNICATION: 2,
        ActionRisk.IRREVERSIBLE_WRITE: 3,
        ActionRisk.PRIVILEGED_OPERATION: 4,
    }

    def verify(self, contract: IntentContract, call: ToolCall) -> PolicyDecision:
        if contract.expired:
            return PolicyDecision(Decision.DENY, "intent contract expired", ("intent", "expiry"))
        if call.tool not in contract.allowed_tools:
            return PolicyDecision(Decision.DENY, f"tool {call.tool} is outside approved purpose", ("intent", "tool_scope"))
        if call.data_class not in contract.allowed_data:
            return PolicyDecision(Decision.DENY, f"data class {call.data_class.value} is outside contract", ("intent", "data_scope"))
        if self.risk_order[call.side_effect] > self.risk_order[contract.max_risk]:
            return PolicyDecision(Decision.ESCALATE, "risk exceeds contract maximum", ("intent", "risk_boundary"))
        if call.side_effect in contract.escalation_required_for:
            return PolicyDecision(Decision.ESCALATE, "contract requires escalation for this action", ("intent", "human_review"))
        if contract.goal.lower().split()[0] not in call.intent.lower():
            return PolicyDecision(Decision.WARN, "declared intent may be drifting from contract goal", ("intent", "drift_detection"))
        return PolicyDecision(Decision.ALLOW, "intent contract satisfied", ("intent",))


class ContextFirewall:
    injection_markers = (
        "ignore previous instructions",
        "exfiltrate",
        "send secrets",
        "disable policy",
        "bypass guardrail",
        "system prompt",
    )

    def inspect(self, item: ContextItem) -> ContextItem:
        findings: list[str] = []
        lowered = item.text.lower()
        for marker in self.injection_markers:
            if marker in lowered:
                findings.append(f"possible instruction injection: {marker}")
        lethal_trifecta = all(term in lowered for term in ("private", "tool", "external"))
        if lethal_trifecta:
            findings.append("lethal-trifecta pattern: private data plus tool plus external sink")
        quarantined = bool(findings) or item.trust_tier == TrustTier.EXTERNAL and item.data_class in {DataClass.PII, DataClass.SECRET}
        trust = TrustTier.QUARANTINED if quarantined else item.trust_tier
        return ContextItem(
            context_id=item.context_id,
            source=item.source,
            text=item.text,
            trust_tier=trust,
            data_class=item.data_class,
            created_at=item.created_at,
            provenance=item.provenance,
            quarantined=quarantined,
            findings=tuple(findings),
        )

    def release(self, items: Iterable[ContextItem], allowed_tiers: frozenset[TrustTier]) -> tuple[list[ContextItem], list[ContextItem]]:
        released: list[ContextItem] = []
        quarantined: list[ContextItem] = []
        for item in items:
            inspected = self.inspect(item)
            if inspected.quarantined or inspected.trust_tier not in allowed_tiers:
                quarantined.append(inspected)
            else:
                released.append(inspected)
        return released, quarantined


class MemoryFirewall:
    def __init__(self, policy_version: str = "training-policy-v1") -> None:
        self.policy_version = policy_version
        self._records: dict[str, MemoryRecord] = {}
        self._history: list[tuple[str, str]] = []

    def propose_write(
        self,
        key: str,
        value: str,
        tenant: str,
        data_class: DataClass,
        trust_tier: TrustTier,
        source: str,
        ttl_seconds: int = 3600,
    ) -> PolicyDecision:
        if data_class in {DataClass.SECRET, DataClass.PII} and trust_tier not in {TrustTier.SYSTEM, TrustTier.TENANT}:
            return PolicyDecision(Decision.DENY, "sensitive memory must come from trusted authority", ("memory", "write_gate"))
        if "ignore previous instructions" in value.lower() or "always approve" in value.lower():
            return PolicyDecision(Decision.DENY, "memory write looks like future-behavior poisoning", ("memory", "poisoning_detection"))
        record_id = stable_id("mem", key, value, tenant)
        self._records[record_id] = MemoryRecord(
            record_id=record_id,
            key=key,
            value=value,
            tenant=tenant,
            data_class=data_class,
            trust_tier=trust_tier,
            source_hash=hashlib.sha256(source.encode("utf-8")).hexdigest(),
            policy_version=self.policy_version,
            created_at=time.time(),
            ttl_seconds=ttl_seconds,
        )
        self._history.append(("write", record_id))
        return PolicyDecision(Decision.ALLOW, f"memory record {record_id} stored", ("memory", "state_ledger"))

    def read(self, key: str, tenant: str, allowed_data: frozenset[DataClass]) -> list[MemoryRecord]:
        result: list[MemoryRecord] = []
        for record in self._records.values():
            if record.deleted or record.expired:
                continue
            if record.key == key and record.tenant == tenant and record.data_class in allowed_data:
                result.append(record)
        return result

    def rollback(self, record_id: str, reason: str) -> PolicyDecision:
        record = self._records.get(record_id)
        if record is None:
            return PolicyDecision(Decision.DENY, "memory record not found", ("memory", "rollback"))
        record.deleted = True
        record.tombstone_reason = reason
        self._history.append(("rollback", record_id))
        return PolicyDecision(Decision.ALLOW, f"memory record {record_id} tombstoned", ("memory", "rollback"))

    @property
    def ledger(self) -> list[MemoryRecord]:
        return list(self._records.values())


class Tracer:
    def __init__(self, run_id: str, actor: str, policy_version: str = "training-policy-v1") -> None:
        self.run_id = run_id
        self.actor = actor
        self.policy_version = policy_version
        self.spans: list[TraceSpan] = []

    @contextlib.contextmanager
    def span(self, name: str, **attributes: Any) -> Iterable[TraceSpan]:
        span = TraceSpan(stable_id("span", self.run_id, name, str(len(self.spans))), name, time.time(), attributes=attributes)
        self.spans.append(span)
        try:
            yield span
        finally:
            span.finish()

    def event(self, span: TraceSpan, name: str, **attributes: Any) -> None:
        span.events.append({"name": name, "at": time.time(), "attributes": attributes})

    def envelope(self, artifacts: dict[str, str] | None = None, redactions: list[str] | None = None) -> EvidenceEnvelope:
        return EvidenceEnvelope(
            run_id=self.run_id,
            actor=self.actor,
            policy_version=self.policy_version,
            spans=self.spans,
            artifact_hashes=artifacts or {},
            redactions=redactions or [],
            created_at=time.time(),
        )


class ToolGateway:
    def __init__(self, tools: Iterable[ToolSpec]) -> None:
        self.tools = {tool.name: tool for tool in tools}

    def check(self, call: ToolCall) -> PolicyDecision:
        spec = self.tools.get(call.tool)
        if spec is None:
            return PolicyDecision(Decision.DENY, f"unknown tool: {call.tool}", ("tool_gateway",))
        if call.side_effect != spec.risk:
            return PolicyDecision(Decision.ESCALATE, "declared side effect differs from tool registration", ("tool_gateway", "side_effect"))
        if call.data_class not in spec.data_classes:
            return PolicyDecision(Decision.DENY, "tool is not approved for this data class", ("tool_gateway", "data_boundary"))
        return PolicyDecision(Decision.ALLOW, "tool gateway accepted call", ("tool_gateway",))


class RuntimeController:
    def __init__(self) -> None:
        self.paused: set[str] = set()
        self.killed: set[str] = set()
        self.checkpoints: dict[str, Checkpoint] = {}
        self.policy_overlays: dict[str, dict[str, Any]] = {}

    def checkpoint(self, run_id: str, state: dict[str, Any], policy_version: str, evidence_hash: str) -> Checkpoint:
        checkpoint = Checkpoint(stable_id("ckpt", run_id, json.dumps(state, sort_keys=True)), run_id, dict(state), policy_version, time.time(), evidence_hash)
        self.checkpoints[checkpoint.checkpoint_id] = checkpoint
        return checkpoint

    def pause(self, run_id: str, reason: str) -> PolicyDecision:
        self.paused.add(run_id)
        return PolicyDecision(Decision.WARN, f"run paused: {reason}", ("runtime_steering", "pause"))

    def kill(self, run_id: str, reason: str) -> PolicyDecision:
        self.killed.add(run_id)
        return PolicyDecision(Decision.DENY, f"run killed: {reason}", ("runtime_steering", "kill_switch"))

    def inject_policy(self, run_id: str, overlay: dict[str, Any], ttl_seconds: int) -> PolicyDecision:
        self.policy_overlays[run_id] = {"overlay": overlay, "expires_at": time.time() + ttl_seconds}
        return PolicyDecision(Decision.ALLOW, "bounded policy overlay injected", ("runtime_steering", "policy_overlay"))

    def resume_from(self, checkpoint_id: str) -> dict[str, Any]:
        checkpoint = self.checkpoints[checkpoint_id]
        self.paused.discard(checkpoint.run_id)
        return dict(checkpoint.state)


class FleetCoordinator:
    def __init__(self, concurrency_limit: int, per_tenant_quota: int) -> None:
        self.concurrency_limit = concurrency_limit
        self.per_tenant_quota = per_tenant_quota
        self.active: dict[str, str] = {}
        self.completed: list[str] = []
        self.queue: deque[tuple[str, str]] = deque()
        self.tenant_counts: dict[str, int] = defaultdict(int)

    def submit(self, tenant: str, task_id: str) -> PolicyDecision:
        if self.tenant_counts[tenant] >= self.per_tenant_quota:
            return PolicyDecision(Decision.ESCALATE, "tenant quota exceeded; apply back-pressure", ("fleet", "quota"))
        if len(self.active) >= self.concurrency_limit:
            self.queue.append((tenant, task_id))
            return PolicyDecision(Decision.WARN, "fleet at capacity; task queued", ("fleet", "back_pressure"))
        self.active[task_id] = tenant
        self.tenant_counts[tenant] += 1
        return PolicyDecision(Decision.ALLOW, "task admitted to fleet", ("fleet", "bulkhead"))

    def complete(self, task_id: str) -> None:
        tenant = self.active.pop(task_id, None)
        if tenant:
            self.tenant_counts[tenant] -= 1
            self.completed.append(task_id)
        while self.queue and len(self.active) < self.concurrency_limit:
            queued_tenant, queued_task = self.queue.popleft()
            if self.tenant_counts[queued_tenant] < self.per_tenant_quota:
                self.active[queued_task] = queued_tenant
                self.tenant_counts[queued_tenant] += 1


class DataGovernanceEngine:
    def __init__(self, egress_allowlist: frozenset[str], residency_rules: dict[DataClass, str]) -> None:
        self.egress_allowlist = egress_allowlist
        self.residency_rules = residency_rules
        self.lineage: list[dict[str, Any]] = []

    def route(self, call: ToolCall, destination: str, region: str) -> PolicyDecision:
        if destination not in self.egress_allowlist:
            return PolicyDecision(Decision.DENY, "destination not on egress allowlist", ("data_governance", "egress"))
        required_region = self.residency_rules.get(call.data_class)
        if required_region and required_region != region:
            return PolicyDecision(Decision.DENY, f"{call.data_class.value} must stay in {required_region}", ("data_governance", "residency"))
        if looks_like_secret(json.dumps(call.args, sort_keys=True)):
            return PolicyDecision(Decision.ESCALATE, "possible secret in outbound payload", ("data_governance", "dlp"))
        self.lineage.append({"tool": call.tool, "data_class": call.data_class.value, "destination": destination, "region": region})
        return PolicyDecision(Decision.ALLOW, "data route approved", ("data_governance", "lineage"))


class Harness:
    def __init__(self) -> None:
        self.broker = CredentialBroker()
        self.intent = IntentVerifier()
        self.context = ContextFirewall()
        self.memory = MemoryFirewall()
        self.runtime = RuntimeController()
        self.gateway = ToolGateway(default_tools())
        self.governance = DataGovernanceEngine(
            frozenset({"internal-ticketing", "internal-repo", "approved-siem", "training-console"}),
            {
                DataClass.PII: "us",
                DataClass.REGULATED: "eu",
                DataClass.SECRET: "vault",
            },
        )


def default_tools() -> list[ToolSpec]:
    return [
        ToolSpec("read_ticket", ActionRisk.READ, frozenset({DataClass.PUBLIC, DataClass.INTERNAL, DataClass.PII}), True, "Read a support or security ticket."),
        ToolSpec("patch_repo", ActionRisk.REVERSIBLE_WRITE, frozenset({DataClass.PUBLIC, DataClass.INTERNAL}), True, "Create a repository patch."),
        ToolSpec("deploy_service", ActionRisk.PRIVILEGED_OPERATION, frozenset({DataClass.INTERNAL}), False, "Deploy a service."),
        ToolSpec("send_customer_email", ActionRisk.EXTERNAL_COMMUNICATION, frozenset({DataClass.PUBLIC, DataClass.INTERNAL, DataClass.PII}), False, "Send outbound customer email."),
        ToolSpec("query_vault", ActionRisk.PRIVILEGED_OPERATION, frozenset({DataClass.SECRET}), False, "Read a secret from a vault."),
        ToolSpec("write_memory", ActionRisk.REVERSIBLE_WRITE, frozenset({DataClass.PUBLIC, DataClass.INTERNAL, DataClass.PII}), True, "Persist memory."),
        ToolSpec("emit_trace", ActionRisk.READ, frozenset({DataClass.PUBLIC, DataClass.INTERNAL, DataClass.CONFIDENTIAL}), True, "Emit trace evidence."),
    ]


def stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def looks_like_secret(value: str) -> bool:
    lowered = value.lower()
    markers = ("api_key", "secret", "token=", "password", "private_key")
    return any(marker in lowered for marker in markers)


def score_from_checks(checks: Iterable[bool]) -> float:
    """Fraction of a scenario's expected outcomes that held; 0.0 with no checks.

    Every check is a concrete claim about what the harness did (a poisoned
    write was denied, a credential was revoked, an egress was blocked). A
    score below 1.0 means a control failed; 1.0 means every expectation held.
    """
    items = [bool(check) for check in checks]
    if not items:
        return 0.0
    return round(sum(items) / len(items), 3)

