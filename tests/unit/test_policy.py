"""Unit tests: policy matching, priority, deny precedence, path handling, risk, file parsing."""

from __future__ import annotations

import pytest

from mcp_firewall.application.services.policy_service import PolicyEngine, assess_risk
from mcp_firewall.config import parse_policy
from mcp_firewall.domain.entities.mcp_request import McpRequest
from mcp_firewall.domain.enums.decision import PolicyAction, RiskLevel


def req(tool="echo", args=None, server="demo", client="claude", op="tools/call"):
    return McpRequest.create(operation=op, client_id=client, server=server, tool=tool, arguments=args)


def engine(rules, default="require_approval"):
    return PolicyEngine(parse_policy({"default_action": default, "rules": rules}))


def test_default_action_when_nothing_matches():
    d = engine([]).evaluate(req())
    assert d.action is PolicyAction.REQUIRE_APPROVAL and d.rule_id is None
    assert engine([], "deny").evaluate(req()).action is PolicyAction.DENY


def test_explicit_deny_beats_higher_priority_allow():
    e = engine(
        [
            {"id": "a", "action": "allow", "priority": 9999, "tools": ["*"]},
            {"id": "d", "action": "deny", "priority": 1, "tools": ["echo"]},
        ]
    )
    d = e.evaluate(req())
    assert d.action is PolicyAction.DENY and d.rule_id == "d"


def test_priority_then_restrictiveness():
    e = engine(
        [
            {"id": "low-allow", "action": "allow", "priority": 1},
            {"id": "high-approve", "action": "require_approval", "priority": 10},
        ]
    )
    assert e.evaluate(req()).rule_id == "high-approve"
    tie = engine(
        [
            {"id": "allow", "action": "allow", "priority": 5},
            {"id": "approve", "action": "require_approval", "priority": 5},
        ]
    )
    assert tie.evaluate(req()).action is PolicyAction.REQUIRE_APPROVAL


def test_selectors_are_globs_and_case_sensitive():
    e = engine(
        [{"id": "r", "action": "allow", "servers": ["de*"], "tools": ["read_*"], "clients": ["claude"]}]
    )
    assert e.evaluate(req("read_file")).action is PolicyAction.ALLOW
    assert e.evaluate(req("write_file")).rule_id is None
    assert e.evaluate(req("READ_file")).rule_id is None
    assert e.evaluate(req("read_file", client="other")).rule_id is None
    assert e.evaluate(req("read_file", op="resources/read")).action is PolicyAction.ALLOW


def test_disabled_rule_ignored():
    e = engine([{"id": "r", "action": "deny", "enabled": False}])
    assert e.evaluate(req()).rule_id is None


@pytest.mark.parametrize(
    "op,value,arg,expected",
    [
        ("equals", "a", "a", True),
        ("not_equals", "a", "b", True),
        ("starts_with", "pub/", "pub/x", True),
        ("starts_with", "pub/", "x/pub/", False),
        ("ends_with", ".txt", "a.txt", True),
        ("contains", "secret", "my secret", True),
        ("glob", "*.md", "a.md", True),
        ("glob", "*.md", "a.txt", False),
        ("regex", r"^\d+$", "123", True),
        ("regex", r"^\d+$", "12a", False),
        ("in", ["a", "b"], "b", True),
        ("not_in", ["a", "b"], "c", True),
        ("gt", 5, 6, True),
        ("lte", 5, 6, False),
    ],
)
def test_condition_operators(op, value, arg, expected):
    e = engine([{"id": "r", "action": "allow", "when": [{"path": "v", "op": op, "value": value}]}])
    assert (e.evaluate(req(args={"v": arg})).rule_id == "r") is expected


def test_missing_argument_never_matches_positive_ops_but_not_exists_does():
    e = engine([{"id": "r", "action": "allow", "when": [{"path": "v", "op": "equals", "value": "x"}]}])
    assert e.evaluate(req(args={})).rule_id is None
    n = engine([{"id": "n", "action": "deny", "when": [{"path": "v", "op": "not_exists"}]}])
    assert n.evaluate(req(args={})).rule_id == "n"
    assert n.evaluate(req(args={"v": 1})).rule_id is None


def test_dotted_paths_and_list_indexes():
    e = engine([{"id": "r", "action": "deny", "when": [{"path": "a.b.1", "op": "equals", "value": "z"}]}])
    assert e.evaluate(req(args={"a": {"b": ["y", "z"]}})).rule_id == "r"
    assert e.evaluate(req(args={"a": {"b": ["y"]}})).rule_id is None


@pytest.mark.parametrize(
    "path,inside",
    [
        ("/sandbox/a.txt", True),
        ("/sandbox", True),
        ("/sandbox/sub/../a.txt", True),
        ("/sandbox/../etc/passwd", False),
        ("/sandboxevil/a", False),
        ("C:\\Sandbox\\a.txt", False),  # different root form
        ("/sandbox/a\x00.txt", False),
    ],
)
def test_path_within_normalises_and_blocks_traversal(path, inside):
    e = engine(
        [{"id": "r", "action": "allow", "when": [{"path": "p", "op": "path_within", "value": "/sandbox"}]}]
    )
    assert (e.evaluate(req(args={"p": path})).rule_id == "r") is inside


def test_path_within_windows_case_insensitive():
    e = engine(
        [{"id": "r", "action": "allow", "when": [{"path": "p", "op": "path_within", "value": "C:\\Work"}]}]
    )
    assert e.evaluate(req(args={"p": "c:/work/x/../y.txt"})).rule_id == "r"
    assert e.evaluate(req(args={"p": "C:\\Work\\..\\Windows\\a"})).rule_id is None


def test_broken_regex_fails_closed_for_non_allow_rules():
    deny = engine([{"id": "d", "action": "deny", "when": [{"path": "v", "op": "regex", "value": "("}]}])
    assert deny.evaluate(req(args={"v": "x"})).action is PolicyAction.DENY
    allow = engine([{"id": "a", "action": "allow", "when": [{"path": "v", "op": "regex", "value": "("}]}])
    assert allow.evaluate(req(args={"v": "x"})).action is PolicyAction.REQUIRE_APPROVAL


def test_rule_flags_propagate():
    e = engine(
        [
            {
                "id": "r",
                "action": "require_approval",
                "strong_confirmation": True,
                "approver_role": "admin",
                "risk": "high",
            }
        ]
    )
    d = e.evaluate(req())
    assert d.strong_confirmation and d.approver_role == "admin" and d.risk is RiskLevel.HIGH


def test_policy_loading_validates():
    with pytest.raises(ValueError):
        parse_policy({"rules": [{"id": "x", "action": "allow", "when": [{"path": "a", "op": "nope"}]}]})
    with pytest.raises(ValueError):
        parse_policy({"rules": [{"id": "x", "action": "allow"}, {"id": "x", "action": "deny"}]})
    with pytest.raises(ValueError):
        parse_policy({"rules": [{"id": "x", "action": "maybe"}]})


def test_policy_version_changes_with_content():
    a = parse_policy({"rules": [{"id": "x", "action": "allow"}]})
    b = parse_policy({"rules": [{"id": "x", "action": "deny"}]})
    assert a.version != b.version
    assert a.version == parse_policy({"rules": [{"id": "x", "action": "allow"}]}).version


@pytest.mark.parametrize(
    "tool,args,level",
    [
        ("read_file", {"path": "a"}, RiskLevel.LOW),
        ("search_issues", {}, RiskLevel.LOW),
        ("create_issue", {}, RiskLevel.MEDIUM),
        ("delete_repository", {}, RiskLevel.HIGH),
        ("execute_shell", {}, RiskLevel.CRITICAL),
        ("runCommand", {}, RiskLevel.CRITICAL),
        ("db_query", {"sql": "DROP TABLE users"}, RiskLevel.HIGH),
        ("read_file", {"path": "../../etc/passwd"}, RiskLevel.HIGH),
        ("frobnicate", {}, RiskLevel.MEDIUM),
    ],
)
def test_risk_heuristics(tool, args, level):
    got, reasons = assess_risk(req(tool, args))
    assert got is level and reasons
