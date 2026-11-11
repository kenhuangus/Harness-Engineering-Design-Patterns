"""Model adapters: the seam where a model proposes work and the harness decides.

A model adapter turns a task plus context into a proposed tool call. The
proposal is data, not authority: every call the adapter returns still passes
the tool gateway, the intent contract, the capability budget, and the
credential broker before anything executes. That ordering is the point of the
seam. A model that proposes a privileged call outside the contract gets a
denial, not an execution.

The labs ship no live model. ``ScriptedModel`` is the deterministic stand-in:
it returns planned calls in order, so a scenario can exercise the adapter seam
without a model API, a network call, or a secret. A production adapter
implements the same ``ModelAdapter`` protocol against a real model gateway.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .core import ToolCall


class ModelAdapter(Protocol):
    """Propose the next tool call for a task. The harness gates the result."""

    def propose(self, task: str, context: list[str]) -> ToolCall:
        ...


@dataclass
class ScriptedModel:
    """Deterministic stand-in for a model: returns planned calls in order.

    Used by the reference pipeline and by tests. It never calls a network,
    a model API, or any code outside this repository.
    """

    planned_calls: list[ToolCall]
    _index: int = field(default=0, init=False)

    def propose(self, task: str, context: list[str]) -> ToolCall:
        if self._index >= len(self.planned_calls):
            raise IndexError("ScriptedModel has no more planned calls")
        call = self.planned_calls[self._index]
        self._index += 1
        return call

    @property
    def calls_remaining(self) -> int:
        return len(self.planned_calls) - self._index
