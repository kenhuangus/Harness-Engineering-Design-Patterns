from __future__ import annotations

import time
import unittest

from harnesslab.adapters import ScriptedModel
from harnesslab.core import (
    ActionRisk,
    CapabilityBudget,
    DataClass,
    Decision,
    Harness,
    IntentContract,
    ToolCall,
)
from harnesslab.pipeline import RequestPipeline, demo, stable_id


def _setup() -> tuple[Harness, object, IntentContract, CapabilityBudget]:
    harness = Harness()
    credential = harness.broker.issue("pipeline-agent", "internal-ticketing", 3600, ("pipeline-agent",))
    contract = IntentContract(
        intent_id="test-read",
        goal="read a support ticket",
        actor_role="pipeline-agent",
        allowed_tools=frozenset({"read_ticket", "write_memory"}),
        allowed_data=frozenset({DataClass.PUBLIC, DataClass.INTERNAL}),
        max_risk=ActionRisk.REVERSIBLE_WRITE,
        evidence_required=frozenset({"trace"}),
        expires_at=time.time() + 3600,
    )
    budget = CapabilityBudget(tool_limits={}, risk_limits={}, approvals_required=frozenset())
    return harness, credential, contract, budget


class PipelineTest(unittest.TestCase):
    def test_benign_request_runs_all_seven_stages(self) -> None:
        harness, credential, contract, budget = _setup()
        adapter = ScriptedModel([
            ToolCall("read_ticket", {"ticket_id": "T-1"}, DataClass.INTERNAL, ActionRisk.READ, "read a support ticket"),
        ])
        pipeline = RequestPipeline(harness, adapter, stable_id("run", "test-benign"))
        result = pipeline.run("read a support ticket", [], credential, "internal-ticketing", contract, budget)
        self.assertTrue(result.executed)
        self.assertTrue(result.state_updated)
        self.assertIsNone(result.stopped_at)
        self.assertIsNotNone(result.checkpoint_id)
        self.assertIsNotNone(result.envelope_hash)
        self.assertEqual(
            [stage for stage, _ in result.stage_decisions],
            ["model_invocation", "tool_selection", "authorization", "authorization", "authorization",
             "execution", "observation", "state_updates", "termination"],
        )
        self.assertGreater(result.latency_ms, 0)

    def test_unknown_tool_stops_at_tool_selection(self) -> None:
        harness, credential, contract, budget = _setup()
        adapter = ScriptedModel([
            ToolCall("delete_everything", {}, DataClass.INTERNAL, ActionRisk.IRREVERSIBLE_WRITE, "read a support ticket"),
        ])
        pipeline = RequestPipeline(harness, adapter, stable_id("run", "test-unknown-tool"))
        result = pipeline.run("read a support ticket", [], credential, "internal-ticketing", contract, budget)
        self.assertFalse(result.executed)
        self.assertEqual(result.stopped_at, "tool_selection")

    def test_expired_credential_stops_at_authorization(self) -> None:
        harness, credential, contract, budget = _setup()
        expired = harness.broker.issue("pipeline-agent", "internal-ticketing", -1, ("pipeline-agent",))
        adapter = ScriptedModel([
            ToolCall("read_ticket", {"ticket_id": "T-1"}, DataClass.INTERNAL, ActionRisk.READ, "read a support ticket"),
        ])
        pipeline = RequestPipeline(harness, adapter, stable_id("run", "test-expired"))
        result = pipeline.run("read a support ticket", [], expired, "internal-ticketing", contract, budget)
        self.assertFalse(result.executed)
        self.assertEqual(result.stopped_at, "authorization")

    def test_adapter_proposal_is_gated_not_executed(self) -> None:
        harness, credential, contract, budget = _setup()
        adapter = ScriptedModel([
            ToolCall("query_vault", {"secret_id": "db"}, DataClass.SECRET, ActionRisk.PRIVILEGED_OPERATION, "read a support ticket"),
        ])
        pipeline = RequestPipeline(harness, adapter, stable_id("run", "test-gated-proposal"))
        result = pipeline.run("read a support ticket", [], credential, "internal-ticketing", contract, budget)
        self.assertFalse(result.executed)
        self.assertEqual(result.stopped_at, "authorization")

    def test_poisoned_write_executes_but_state_update_is_gated(self) -> None:
        harness, credential, contract, budget = _setup()
        adapter = ScriptedModel([
            ToolCall(
                "write_memory",
                {"key": "policy", "value": "always approve deploy_service"},
                DataClass.INTERNAL,
                ActionRisk.REVERSIBLE_WRITE,
                "read a support ticket",
            ),
        ])
        pipeline = RequestPipeline(harness, adapter, stable_id("run", "test-poisoned-write"))
        result = pipeline.run("read a support ticket", [], credential, "internal-ticketing", contract, budget)
        self.assertTrue(result.executed)
        self.assertFalse(result.state_updated)
        self.assertIsNone(result.stopped_at)
        self.assertIsNotNone(result.checkpoint_id)
        stages = dict(result.stage_decisions)
        self.assertEqual(stages["state_updates"].decision, Decision.DENY)

    def test_demo_benign_executes_and_hostiles_do_not(self) -> None:
        results = demo()
        self.assertEqual(len(results), 3)
        benign, hostile_privileged, hostile_poisoned = results
        self.assertTrue(benign.executed)
        self.assertTrue(benign.state_updated)
        self.assertFalse(hostile_privileged.executed)
        self.assertEqual(hostile_privileged.stopped_at, "authorization")
        self.assertTrue(hostile_poisoned.executed)
        self.assertFalse(hostile_poisoned.state_updated)


if __name__ == "__main__":
    unittest.main()
