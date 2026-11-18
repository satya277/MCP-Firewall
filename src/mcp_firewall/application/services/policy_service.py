"""Deterministic policy engine.

Resolution order (documented in docs/security.md):
1. Every enabled rule whose selectors and conditions all match is collected.
2. If any matching rule says DENY, the request is denied (explicit deny always wins).
3. Otherwise the highest-priority match wins; ties resolve to the most restrictive action.
4. With no match the policy's default action applies (``require_approval`` unless configured).
"""

from __future__ import annotations

import fnmatch
import ntpath
import posixpath
import re
from typing import Any

from mcp_firewall.domain.entities.mcp_request import McpRequest
from mcp_firewall.domain.entities.policy import Condition, PolicyDecision, PolicyRule, PolicySet
from mcp_firewall.domain.enums.decision import PolicyAction, RiskLevel

_RESTRICTIVENESS = {PolicyAction.ALLOW: 0, PolicyAction.REQUIRE_APPROVAL: 1, PolicyAction.DENY: 2}
_MAX_REGEX_INPUT = 10_000
_MISSING = object()


def _lookup(arguments: Any, path: str) -> Any:
    current = arguments
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


def _norm_path(value: str) -> str:
    # Normalise lexically (resolves '..' and separators) without touching the filesystem.
    unified = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:", unified):
        return ntpath.normpath(unified).replace("\\", "/").lower()
    return posixpath.normpath(unified)


def _path_within(candidate: str, root: str) -> bool:
    if "\x00" in candidate:
        return False
    cand, base = _norm_path(candidate), _norm_path(root).rstrip("/")
    return cand == base or cand.startswith(base + "/")


def _compare(op: str, actual: Any, expected: Any) -> bool:
    if op == "equals":
        return actual == expected
    if op == "not_equals":
        return actual != expected
    if op == "in":
        return actual in (expected or [])
    if op == "not_in":
        return actual not in (expected or [])
    if op in {"gt", "gte", "lt", "lte"}:
        if isinstance(actual, bool) or not isinstance(actual, (int, float)):
            return False
        return {
            "gt": actual > expected,
            "gte": actual >= expected,
            "lt": actual < expected,
            "lte": actual <= expected,
        }[op]
    if not isinstance(actual, str):
        return False
    if op == "starts_with":
        return actual.startswith(str(expected))
    if op == "ends_with":
        return actual.endswith(str(expected))
    if op == "contains":
        return str(expected) in actual
    if op == "glob":
        return fnmatch.fnmatchcase(actual, str(expected))
    if op == "regex":
        return re.search(str(expected), actual[:_MAX_REGEX_INPUT]) is not None
    if op == "path_within":
        roots = expected if isinstance(expected, list) else [expected]
        return any(_path_within(actual, str(root)) for root in roots)
    raise ValueError(f"unknown condition operator: {op}")


KNOWN_OPERATORS = frozenset(
    {
        "equals", "not_equals", "in", "not_in", "gt", "gte", "lt", "lte", "starts_with", "ends_with",
        "contains", "glob", "regex", "path_within", "exists", "not_exists",
    }
)  # fmt: skip


def condition_matches(cond: Condition, arguments: dict[str, Any]) -> bool:
    actual = _lookup(arguments, cond.path)
    if cond.op == "exists":
        return actual is not _MISSING
    if cond.op == "not_exists":
        return actual is _MISSING
    if actual is _MISSING:
        return False
    return _compare(cond.op, actual, cond.value)


def _globs(patterns: tuple[str, ...], value: str) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def rule_matches(rule: PolicyRule, request: McpRequest, arguments: dict[str, Any]) -> bool:
    if not rule.enabled:
        return False
    if not (
        _globs(rule.servers, request.server)
        and _globs(rule.tools, request.tool)
        and _globs(rule.clients, request.client_id)
        and _globs(rule.operations, request.operation)
    ):
        return False
    return all(condition_matches(c, arguments) for c in rule.conditions)


class PolicyEngine:
    """Pure, side-effect-free evaluation of a PolicySet."""

    def __init__(self, policy: PolicySet) -> None:
        self._policy = policy

    @property
    def policy(self) -> PolicySet:
        return self._policy

    def replace(self, policy: PolicySet) -> None:
        self._policy = policy

    def evaluate(self, request: McpRequest) -> PolicyDecision:
        policy = self._policy
        arguments = request.arguments
        matched: list[PolicyRule] = []
        for rule in policy.rules:
            try:
                if rule_matches(rule, request, arguments):
                    matched.append(rule)
            except (re.error, ValueError, TypeError):
                # A broken rule must never silently weaken protection; treat as require_approval.
                if rule.action is not PolicyAction.ALLOW:
                    matched.append(rule)
        ids = tuple(r.id for r in matched)
        if not matched:
            return PolicyDecision(
                policy.default_action, None, "no rule matched; default action", policy.version, matched=ids
            )

        denies = [r for r in matched if r.action is PolicyAction.DENY]
        if denies:
            winner = max(denies, key=lambda r: r.priority)
            return self._decision(winner, policy, ids, "explicit deny")

        winner = max(matched, key=lambda r: (r.priority, _RESTRICTIVENESS[r.action]))
        return self._decision(winner, policy, ids, "highest-priority matching rule")

    @staticmethod
    def _decision(rule: PolicyRule, policy: PolicySet, ids: tuple[str, ...], why: str) -> PolicyDecision:
        return PolicyDecision(
            action=rule.action,
            rule_id=rule.id,
            reason=f"{why}: {rule.description or rule.id}",
            policy_version=policy.version,
            strong_confirmation=rule.strong_confirmation,
            approver_role=rule.approver_role,
            risk=rule.risk,
            matched=ids,
        )


_HIGH_TOKENS = (
    "delete",
    "remove",
    "drop",
    "destroy",
    "truncate",
    "wipe",
    "kill",
    "format",
    "purge",
    "revoke",
)
_EXEC_TOKENS = ("exec", "shell", "bash", "powershell", "command", "eval", "run_script", "terminal", "spawn")
_WRITE_TOKENS = (
    "write", "create", "update", "edit", "send", "post", "put", "push", "commit", "transfer", "pay",
    "deploy", "upload", "install", "set", "insert", "move", "rename", "chmod", "merge",
)  # fmt: skip
_READ_TOKENS = ("read", "get", "list", "search", "find", "fetch", "describe", "show", "view", "query", "stat")
_DESTRUCTIVE_SQL = re.compile(r"\b(delete|drop|truncate|alter|update|insert)\b", re.IGNORECASE)


def _name_tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", name).lower()) if t]


def assess_risk(request: McpRequest) -> tuple[RiskLevel, list[str]]:
    """Heuristic, advisory-only risk explanation for the approver. It never grants permission."""
    tokens = _name_tokens(request.tool)
    reasons: list[str] = []
    level = RiskLevel.MEDIUM

    def has(words: tuple[str, ...]) -> bool:
        return any(t.startswith(w) for t in tokens for w in words)

    if has(_EXEC_TOKENS):
        level, reasons = RiskLevel.CRITICAL, ["Tool appears to execute commands or code"]
    elif has(_HIGH_TOKENS):
        level, reasons = RiskLevel.HIGH, ["Tool name suggests a destructive operation"]
    elif has(_WRITE_TOKENS):
        level, reasons = RiskLevel.MEDIUM, ["Tool name suggests it changes state"]
    elif has(_READ_TOKENS):
        level, reasons = RiskLevel.LOW, ["Tool name suggests a read-only operation"]
    else:
        reasons = ["Effect of this tool is unknown"]

    args = request.canonical_arguments
    if (
        _DESTRUCTIVE_SQL.search(args)
        and level < RiskLevel.HIGH
        and any(k in args.lower() for k in ('"sql"', '"query"', '"statement"'))
    ):
        level = RiskLevel.HIGH
        reasons.append("Arguments contain data-modifying SQL keywords")
    if ".." in args and any(k in args for k in ("/", "\\\\")):
        level = max(level, RiskLevel.HIGH)
        reasons.append("Arguments contain a path-traversal pattern")
    if request.operation == "resources/read":
        reasons.append("Reads a resource and may disclose data to the model")
    return level, reasons
