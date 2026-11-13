from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from harnesslab.core import Decision, LabResult, PolicyDecision, score_from_checks


@dataclass(frozen=True)
class WorkItem:
    task_id: str
    tenant: str
    operation: str
    idempotency_key: str
    payload: str
    capacity_units: int
    expected_minutes: int
    tools: tuple[str, ...]

    @property
    def payload_hash(self) -> str:
        return hashlib.sha256(self.payload.encode("utf-8")).hexdigest()[:16]


@dataclass
class Worker:
    worker_id: str
    tenant_bulkhead: str
    active_task: str | None = None
    quarantined: bool = False


class IdempotencyLedger:
    def __init__(self, retry_limit: int) -> None:
        self.retry_limit = retry_limit
        self.records: dict[str, dict[str, Any]] = {}

    def start(self, item: WorkItem) -> PolicyDecision:
        record = self.records.get(item.idempotency_key)
        if record is None:
            self.records[item.idempotency_key] = {
                "task_id": item.task_id,
                "payload_hash": item.payload_hash,
                "attempts": 1,
                "status": "in_progress",
            }
            return PolicyDecision(
                Decision.ALLOW,
                f"idempotency key recorded for {item.task_id}",
                ("idempotency", "retry_ledger"),
            )

        if record["payload_hash"] != item.payload_hash:
            return PolicyDecision(
                Decision.DENY,
                "idempotency key reused with a different payload",
                ("idempotency", "replay_protection", "unsafe_retry_blocked"),
            )

        if record["status"] == "completed":
            return PolicyDecision(
                Decision.ALLOW,
                "idempotent retry replayed completed result without duplicate side effects",
                ("idempotency", "side_effect_suppression"),
            )

        if record["attempts"] >= self.retry_limit:
            return PolicyDecision(
                Decision.ESCALATE,
                "retry limit reached for in-flight idempotency key",
                ("idempotency", "retry_budget", "human_review"),
            )

        record["attempts"] += 1
        return PolicyDecision(
            Decision.WARN,
            "idempotent retry allowed after worker lease loss",
            ("idempotency", "retry", "side_effect_suppression"),
        )

    def complete(self, item: WorkItem) -> PolicyDecision:
        record = self.records[item.idempotency_key]
        record["status"] = "completed"
        return PolicyDecision(
            Decision.ALLOW,
            f"idempotency key completed for {item.task_id}",
            ("idempotency", "commit_log"),
        )

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {key: dict(value) for key, value in sorted(self.records.items())}


class RateWindow:
    def __init__(self, limits: dict[str, int]) -> None:
        self.limits = limits
        self.window_by_tool: dict[str, int] = defaultdict(lambda: 1)
        self.used_by_tool: dict[str, int] = defaultdict(int)
        self.delayed: list[dict[str, Any]] = []

    def check(self, item: WorkItem) -> list[PolicyDecision]:
        decisions: list[PolicyDecision] = []
        for tool in item.tools:
            limit = self.limits.get(tool)
            if limit is None:
                continue
            if self.used_by_tool[tool] >= limit:
                self.window_by_tool[tool] += 1
                self.used_by_tool[tool] = 0
                self.delayed.append(
                    {
                        "task_id": item.task_id,
                        "tool": tool,
                        "resumed_in_window": self.window_by_tool[tool],
                    }
                )
                decisions.append(
                    PolicyDecision(
                        Decision.WARN,
                        f"rate limit reached for {tool}; task delayed to next window",
                        ("rate_limit", "back_pressure", "queue"),
                    )
                )
            self.used_by_tool[tool] += 1
            decisions.append(
                PolicyDecision(
                    Decision.ALLOW,
                    f"rate window admitted {tool} for {item.task_id}",
                    ("rate_limit",),
                )
            )
        return decisions

    def snapshot(self) -> dict[str, Any]:
        tools = sorted(set(self.limits) | set(self.window_by_tool) | set(self.used_by_tool))
        return {
            "windows": {tool: self.window_by_tool[tool] for tool in tools},
            "used": {tool: self.used_by_tool[tool] for tool in tools},
            "delayed": list(self.delayed),
        }


class CapacityGovernor:
    def __init__(self, epoch_limit: int, checkpoint_minutes: int) -> None:
        self.epoch_limit = epoch_limit
        self.checkpoint_minutes = checkpoint_minutes
        self.epoch = 1
        self.remaining = epoch_limit
        self.checkpoints: list[dict[str, Any]] = []
        self.epoch_rollovers: list[dict[str, Any]] = []

    def reserve(self, item: WorkItem, retry: bool) -> list[PolicyDecision]:
        if retry:
            return [
                PolicyDecision(
                    Decision.ALLOW,
                    "retry reused the original capacity reservation",
                    ("capacity_governance", "idempotency", "retry"),
                )
            ]

        decisions: list[PolicyDecision] = []
        if item.expected_minutes >= self.checkpoint_minutes:
            checkpoint = {
                "task_id": item.task_id,
                "epoch": self.epoch,
                "reason": "long-running task requires resumable checkpoint",
            }
            self.checkpoints.append(checkpoint)
            decisions.append(
                PolicyDecision(
                    Decision.WARN,
                    "long-running work requires checkpoint before execution",
                    ("long_running_capacity", "checkpoint", "capacity_governance"),
                )
            )

        if item.capacity_units > self.remaining:
            self.epoch_rollovers.append(
                {
                    "task_id": item.task_id,
                    "from_epoch": self.epoch,
                    "remaining_before_rollover": self.remaining,
                }
            )
            decisions.append(
                PolicyDecision(
                    Decision.WARN,
                    "capacity budget exhausted; work deferred to next governance epoch",
                    ("long_running_capacity", "capacity_governance", "back_pressure"),
                )
            )
            self.epoch += 1
            self.remaining = self.epoch_limit

        self.remaining -= item.capacity_units
        decisions.append(
            PolicyDecision(
                Decision.ALLOW,
                f"capacity reserved in epoch {self.epoch} for {item.task_id}",
                ("capacity_governance", "quota"),
            )
        )
        return decisions

    def snapshot(self) -> dict[str, Any]:
        return {
            "epoch": self.epoch,
            "remaining": self.remaining,
            "epoch_limit": self.epoch_limit,
            "checkpoints": list(self.checkpoints),
            "epoch_rollovers": list(self.epoch_rollovers),
        }


class FleetControlPlane:
    def __init__(
        self,
        workers: list[Worker],
        global_active_limit: int,
        tenant_active_limits: dict[str, int],
        tenant_capacity_quotas: dict[str, int],
        queue_limit: int,
    ) -> None:
        self.workers = {worker.worker_id: worker for worker in workers}
        self.global_active_limit = global_active_limit
        self.tenant_active_limits = tenant_active_limits
        self.tenant_capacity_quotas = tenant_capacity_quotas
        self.queue_limit = queue_limit
        self.active: dict[str, WorkItem] = {}
        self.task_worker: dict[str, str] = {}
        self.completed: list[str] = []
        self.queue: deque[WorkItem] = deque()
        self.tenant_active: dict[str, int] = defaultdict(int)
        self.tenant_reserved: dict[str, int] = defaultdict(int)
        self.promotions: list[dict[str, str]] = []

    def submit(self, item: WorkItem) -> tuple[PolicyDecision, list[tuple[PolicyDecision, WorkItem, bool]]]:
        quota = self.tenant_capacity_quotas[item.tenant]
        if self.tenant_reserved[item.tenant] + item.capacity_units > quota:
            return (
                PolicyDecision(
                    Decision.ESCALATE,
                    f"tenant {item.tenant} capacity quota exceeded",
                    ("fleet", "quota", "long_running_capacity", "human_review"),
                ),
                [],
            )

        self.tenant_reserved[item.tenant] += item.capacity_units
        if self.tenant_active[item.tenant] >= self.tenant_active_limits[item.tenant]:
            return self._queue(item, f"tenant {item.tenant} bulkhead is saturated")
        worker = self._available_worker(item)
        if len(self.active) >= self.global_active_limit:
            return self._queue(item, "global fleet capacity is saturated")
        if worker is None:
            return self._queue(item, f"no clean worker is available for tenant {item.tenant}")

        self._assign(worker, item)
        return (
            PolicyDecision(
                Decision.ALLOW,
                f"task {item.task_id} admitted to {worker.worker_id}",
                ("fleet", "bulkhead", "quota"),
            ),
            [],
        )

    def complete(self, task_id: str) -> list[tuple[PolicyDecision, WorkItem | None, bool]]:
        item = self.active.pop(task_id)
        worker_id = self.task_worker.pop(task_id)
        worker = self.workers[worker_id]
        worker.active_task = None
        self.tenant_active[item.tenant] -= 1
        self.completed.append(task_id)
        decisions: list[tuple[PolicyDecision, WorkItem | None, bool]] = [
            (
                PolicyDecision(
                    Decision.ALLOW,
                    f"task {task_id} released worker {worker_id}",
                    ("fleet", "worker_release"),
                ),
                None,
                False,
            )
        ]
        decisions.extend(self._promote_ready())
        return decisions

    def contain_worker(self, worker_id: str, reason: str) -> tuple[PolicyDecision, WorkItem | None]:
        worker = self.workers[worker_id]
        worker.quarantined = True
        task_id = worker.active_task
        if task_id is None:
            return (
                PolicyDecision(
                    Decision.WARN,
                    f"worker {worker_id} quarantined while idle: {reason}",
                    ("fleet", "compromised_worker", "containment"),
                ),
                None,
            )

        item = self.active.pop(task_id)
        self.task_worker.pop(task_id)
        self.tenant_active[item.tenant] -= 1
        worker.active_task = None
        self.queue.appendleft(item)
        return (
            PolicyDecision(
                Decision.DENY,
                f"worker {worker_id} quarantined; lease for {task_id} revoked and requeued",
                ("fleet", "bulkhead", "compromised_worker", "containment", "queue"),
            ),
            item,
        )

    def _queue(self, item: WorkItem, reason: str) -> tuple[PolicyDecision, list[tuple[PolicyDecision, WorkItem, bool]]]:
        if len(self.queue) >= self.queue_limit:
            return (
                PolicyDecision(
                    Decision.ESCALATE,
                    "queue limit reached; operator capacity review required",
                    ("fleet", "queue", "back_pressure", "human_review"),
                ),
                [],
            )
        self.queue.append(item)
        return (
            PolicyDecision(
                Decision.WARN,
                f"{reason}; task {item.task_id} queued with back-pressure",
                ("fleet", "queue", "back_pressure", "bulkhead"),
            ),
            [],
        )

    def _available_worker(self, item: WorkItem) -> Worker | None:
        for worker in self.workers.values():
            if worker.tenant_bulkhead != item.tenant:
                continue
            if worker.quarantined or worker.active_task is not None:
                continue
            return worker
        return None

    def _assign(self, worker: Worker, item: WorkItem) -> None:
        worker.active_task = item.task_id
        self.active[item.task_id] = item
        self.task_worker[item.task_id] = worker.worker_id
        self.tenant_active[item.tenant] += 1

    def _promote_ready(self) -> list[tuple[PolicyDecision, WorkItem, bool]]:
        promoted: list[tuple[PolicyDecision, WorkItem, bool]] = []
        retained: deque[WorkItem] = deque()
        while self.queue:
            item = self.queue.popleft()
            worker = self._available_worker(item)
            if len(self.active) >= self.global_active_limit or worker is None:
                retained.append(item)
                continue
            if self.tenant_active[item.tenant] >= self.tenant_active_limits[item.tenant]:
                retained.append(item)
                continue
            self._assign(worker, item)
            self.promotions.append({"task_id": item.task_id, "worker_id": worker.worker_id})
            promoted.append(
                (
                    PolicyDecision(
                        Decision.ALLOW,
                        f"queued task {item.task_id} promoted to {worker.worker_id}",
                        ("fleet", "queue", "back_pressure", "bulkhead"),
                    ),
                    item,
                    True,
                )
            )
        self.queue = retained
        return promoted

    def snapshot(self) -> dict[str, Any]:
        return {
            "active": {task_id: self.task_worker[task_id] for task_id in sorted(self.active)},
            "completed": list(self.completed),
            "queued": [item.task_id for item in self.queue],
            "quarantined_workers": [
                worker_id
                for worker_id, worker in sorted(self.workers.items())
                if worker.quarantined
            ],
            "tenant_reserved": dict(sorted(self.tenant_reserved.items())),
            "promotions": list(self.promotions),
        }


def _begin_execution(
    item: WorkItem,
    retry: bool,
    ledger: IdempotencyLedger,
    rate_window: RateWindow,
    capacity: CapacityGovernor,
) -> list[PolicyDecision]:
    decisions = [ledger.start(item)]
    if decisions[-1].decision in {Decision.DENY, Decision.ESCALATE}:
        return decisions
    decisions.extend(capacity.reserve(item, retry=retry and decisions[0].decision != Decision.ALLOW))
    decisions.extend(rate_window.check(item))
    return decisions


def _controls(decisions: list[PolicyDecision]) -> set[str]:
    return {control for decision in decisions for control in decision.controls}


def run() -> LabResult:
    ledger = IdempotencyLedger(retry_limit=3)
    rate_window = RateWindow({"read_ticket": 2, "patch_repo": 1, "deploy_service": 1})
    capacity = CapacityGovernor(epoch_limit=6, checkpoint_minutes=6)
    fleet = FleetControlPlane(
        workers=[
            Worker("acme-worker-1", "acme"),
            Worker("acme-worker-2", "acme"),
            Worker("globex-worker-1", "globex"),
        ],
        global_active_limit=2,
        tenant_active_limits={"acme": 2, "globex": 1},
        tenant_capacity_quotas={"acme": 8, "globex": 6},
        queue_limit=4,
    )
    decisions: list[PolicyDecision] = []

    def submit(item: WorkItem) -> None:
        decision, promoted = fleet.submit(item)
        decisions.append(decision)
        if decision.decision == Decision.ALLOW:
            decisions.extend(_begin_execution(item, False, ledger, rate_window, capacity))
        for promotion_decision, promoted_item, retry in promoted:
            decisions.append(promotion_decision)
            decisions.extend(_begin_execution(promoted_item, retry, ledger, rate_window, capacity))

    def complete(item: WorkItem) -> None:
        decisions.append(ledger.complete(item))
        for promotion_decision, promoted_item, retry in fleet.complete(item.task_id):
            decisions.append(promotion_decision)
            if promoted_item is not None:
                decisions.extend(_begin_execution(promoted_item, retry, ledger, rate_window, capacity))

    acme_triage = WorkItem(
        "acme-triage-001",
        "acme",
        "triage customer incident",
        "acme:incident-77:triage",
        "read incident 77 and classify blast radius",
        capacity_units=2,
        expected_minutes=3,
        tools=("read_ticket",),
    )
    acme_patch = WorkItem(
        "acme-patch-002",
        "acme",
        "prepare safe repository patch",
        "acme:incident-77:patch",
        "patch service acl and attach evidence bundle",
        capacity_units=4,
        expected_minutes=9,
        tools=("read_ticket", "patch_repo"),
    )
    globex_triage = WorkItem(
        "globex-triage-003",
        "globex",
        "triage customer incident",
        "globex:incident-12:triage",
        "read incident 12 and classify blast radius",
        capacity_units=2,
        expected_minutes=4,
        tools=("read_ticket",),
    )
    acme_followup = WorkItem(
        "acme-followup-004",
        "acme",
        "prepare second safe patch",
        "acme:incident-78:patch",
        "patch worker timeout and attach replay log",
        capacity_units=2,
        expected_minutes=5,
        tools=("patch_repo",),
    )
    acme_over_quota = WorkItem(
        "acme-analysis-005",
        "acme",
        "launch large retrospective analysis",
        "acme:incident-79:analysis",
        "analyze every historical incident before shift handoff",
        capacity_units=1,
        expected_minutes=30,
        tools=("read_ticket", "deploy_service"),
    )
    unsafe_retry = WorkItem(
        "acme-patch-002-poisoned",
        "acme",
        "poison retry payload",
        "acme:incident-77:patch",
        "patch service acl and also disable policy checks",
        capacity_units=1,
        expected_minutes=1,
        tools=("patch_repo",),
    )

    submit(acme_triage)
    submit(acme_patch)
    submit(globex_triage)
    submit(acme_followup)
    submit(acme_over_quota)

    containment_decision, contained_item = fleet.contain_worker(
        "acme-worker-2",
        "worker emitted a tool request containing 'disable policy'",
    )
    decisions.append(containment_decision)
    contained = contained_item is not None

    complete(acme_triage)
    decisions.append(ledger.start(unsafe_retry))

    complete(globex_triage)
    complete(acme_patch)
    complete(acme_followup)

    controls = _controls(decisions)
    required_controls = {
        "fleet",
        "queue",
        "bulkhead",
        "quota",
        "back_pressure",
        "idempotency",
        "retry",
        "compromised_worker",
        "containment",
        "rate_limit",
        "long_running_capacity",
        "capacity_governance",
        "checkpoint",
    }
    unsafe_retry_blocked = any("unsafe_retry_blocked" in decision.controls for decision in decisions)
    quota_escalated = any(decision.decision == Decision.ESCALATE and "quota" in decision.controls for decision in decisions)
    checks = [
        required_controls.issubset(controls),
        contained,
        unsafe_retry_blocked,
        quota_escalated,
    ]
    passed = all(checks)

    return LabResult(
        chapter="ch09",
        title="Scalability: Fleet Coordination Without Cascading Failure",
        passed=passed,
        score=score_from_checks(checks),
        summary=(
            "Fleet coordination exercised tenant bulkheads, queues, quotas, rate limits, "
            "idempotent retries, compromised-worker containment, and long-running capacity governance."
        ),
        decisions=decisions,
        artifacts={
            "fleet": fleet.snapshot(),
            "idempotency_ledger": ledger.snapshot(),
            "rate_limits": rate_window.snapshot(),
            "capacity_governance": capacity.snapshot(),
            "controls_exercised": sorted(controls),
            "required_controls": sorted(required_controls),
            "unsafe_paths": {
                "compromised_worker_contained": contained,
                "poisoned_retry_blocked": unsafe_retry_blocked,
                "quota_escalated": quota_escalated,
            },
        },
    )


if __name__ == "__main__":
    print(run().to_json())
