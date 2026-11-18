"""Policy entities: deterministic rules and the decision they produce."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_firewall.domain.enums.decision import PolicyAction, RiskLevel


@dataclass(frozen=True, slots=True)
class Condition:
    """A predicate over one (dotted-path) argument, e.g. ``path path_within /sandbox``."""

    path: str
    op: str
    value: Any = None


@dataclass(frozen=True, slots=True)
class PolicyRule:
    id: str
    action: PolicyAction
    priority: int = 0
    description: str = ""
    servers: tuple[str, ...] = ("*",)
    tools: tuple[str, ...] = ("*",)
    clients: tuple[str, ...] = ("*",)
    operations: tuple[str, ...] = ("*",)
    conditions: tuple[Condition, ...] = ()
    risk: RiskLevel | None = None
    strong_confirmation: bool = False
    approver_role: str = "approver"
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PolicyAction
    rule_id: str | None
    reason: str
    policy_version: str
    strong_confirmation: bool = False
    approver_role: str = "approver"
    risk: RiskLevel | None = None
    matched: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class PolicySet:
    version: str
    rules: tuple[PolicyRule, ...]
    default_action: PolicyAction = PolicyAction.REQUIRE_APPROVAL
