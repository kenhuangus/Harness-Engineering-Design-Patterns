from __future__ import annotations

import unittest

from harnesslab.adapters import ScriptedModel
from harnesslab.core import ActionRisk, DataClass, Decision, ToolCall, TrustTier
from harnesslab.extensions import Extension, ExtensionRegistry


class BoundariesTest(unittest.TestCase):
    def test_scripted_model_returns_calls_in_order_then_stops(self) -> None:
        call = ToolCall("read_ticket", {}, DataClass.PUBLIC, ActionRisk.READ, "read")
        model = ScriptedModel([call])
        self.assertEqual(model.calls_remaining, 1)
        self.assertEqual(model.propose("read", []), call)
        self.assertEqual(model.calls_remaining, 0)
        with self.assertRaises(IndexError):
            model.propose("read", [])

    def test_registry_denies_unpinned_extension(self) -> None:
        registry = ExtensionRegistry()
        decision = registry.register(Extension("tool-x", "", TrustTier.EXTERNAL, True, "abc"))
        self.assertEqual(decision.decision, Decision.DENY)

    def test_registry_denies_unreviewed_extension(self) -> None:
        registry = ExtensionRegistry()
        decision = registry.register(Extension("tool-x", "1.0.0", TrustTier.EXTERNAL, False, "abc"))
        self.assertEqual(decision.decision, Decision.DENY)

    def test_registry_admits_reviewed_pinned_extension_and_loads_it(self) -> None:
        registry = ExtensionRegistry()
        decision = registry.register(Extension("tool-x", "1.0.0", TrustTier.TRUSTED_TOOL, True, "abc"))
        self.assertEqual(decision.decision, Decision.ALLOW)
        extension, load_decision = registry.load("tool-x")
        self.assertIsNotNone(extension)
        self.assertEqual(load_decision.decision, Decision.ALLOW)
        self.assertEqual(registry.admitted, ["tool-x"])

    def test_registry_denies_unknown_extension_at_load(self) -> None:
        registry = ExtensionRegistry()
        extension, decision = registry.load("tool-never-registered")
        self.assertIsNone(extension)
        self.assertEqual(decision.decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()
