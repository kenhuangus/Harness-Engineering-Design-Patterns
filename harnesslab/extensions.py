"""Extension supply-chain controls: no extension runs without review.

An extension is any code the harness loads beyond its own modules: a tool
implementation, a scenario, a retriever, a model adapter. This registry is
the admission gate. An extension is admitted only when it is pinned to a
version, reviewed by a human, and assigned a trust tier. Anything else —
unpinned, unreviewed, or unknown — is denied at load time, before it runs.

The chapter scenarios are in-repo modules, so they are the pinned,
reviewed extensions in this repository. The registry models the same gate a
production harness applies at its extension boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import Decision, PolicyDecision, TrustTier


@dataclass(frozen=True)
class Extension:
    name: str
    version: str
    trust_tier: TrustTier
    reviewed: bool
    source_hash: str


class ExtensionRegistry:
    """Admit extensions only when pinned, reviewed, and tiered."""

    def __init__(self) -> None:
        self._extensions: dict[str, Extension] = {}
        self.load_decisions: list[PolicyDecision] = []

    def register(self, extension: Extension) -> PolicyDecision:
        if not extension.version:
            decision = PolicyDecision(
                Decision.DENY, f"extension {extension.name} has no pinned version", ("extension_supply_chain", "pinning")
            )
            self.load_decisions.append(decision)
            return decision
        if not extension.reviewed:
            decision = PolicyDecision(
                Decision.DENY, f"extension {extension.name} is unreviewed", ("extension_supply_chain", "review")
            )
            self.load_decisions.append(decision)
            return decision
        self._extensions[extension.name] = extension
        decision = PolicyDecision(
            Decision.ALLOW, f"extension {extension.name} {extension.version} admitted", ("extension_supply_chain",)
        )
        self.load_decisions.append(decision)
        return decision

    def load(self, name: str) -> tuple[Extension | None, PolicyDecision]:
        extension = self._extensions.get(name)
        if extension is None:
            decision = PolicyDecision(
                Decision.DENY, f"unknown extension: {name}", ("extension_supply_chain", "admission")
            )
            self.load_decisions.append(decision)
            return None, decision
        decision = PolicyDecision(
            Decision.ALLOW, f"extension {name} loaded", ("extension_supply_chain",)
        )
        self.load_decisions.append(decision)
        return extension, decision

    @property
    def admitted(self) -> list[str]:
        return sorted(self._extensions)
