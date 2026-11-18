"""Unit tests: canonical hashing, request integrity and the lifecycle state machine."""

from __future__ import annotations

import pytest

from mcp_firewall.domain.canonical import canonical_json
from mcp_firewall.domain.entities.mcp_request import McpRequest, RequestRecord
from mcp_firewall.domain.enums.request_status import ALLOWED_TRANSITIONS, RequestStatus, can_transition
from mcp_firewall.domain.exceptions import IntegrityError, InvalidRequestError, InvalidTransitionError


def make(args=None, **kw) -> McpRequest:
    base = {
        "operation": "tools/call",
        "client_id": "claude",
        "server": "demo",
        "tool": "echo",
        "arguments": args,
    }
    base.update(kw)
    return McpRequest.create(**base)


def test_hash_is_deterministic_and_order_independent():
    a = make({"x": 1, "y": [1, 2, {"b": 1, "a": 2}]})
    b = make({"y": [1, 2, {"a": 2, "b": 1}], "x": 1})
    assert a.request_hash == b.request_hash
    assert a.canonical_arguments == b.canonical_arguments


@pytest.mark.parametrize(
    "changed",
    [
        {"args": {"x": 2}},
        {"server": "other"},
        {"tool": "echo2"},
        {"client_id": "someone-else"},
        {"operation": "resources/read"},
    ],
)
def test_any_change_alters_hash(changed):
    base = make({"x": 1})
    kw = {"args": {"x": 1}} | changed
    other = make(kw.pop("args"), **kw)
    assert other.request_hash != base.request_hash


def test_unicode_and_types_are_distinguished():
    assert make({"v": "1"}).request_hash != make({"v": 1}).request_hash
    assert make({"v": "é"}).request_hash == make({"v": "é"}).request_hash


@pytest.mark.parametrize("bad", [{"v": float("nan")}, {"v": float("inf")}, {"v": object()}, {1: "x"}])
def test_rejects_non_json_arguments(bad):
    with pytest.raises(InvalidRequestError):
        make(bad)


def test_rejects_deep_nesting_and_oversize():
    deep: dict = {}
    cur = deep
    for _ in range(50):
        cur["n"] = {}
        cur = cur["n"]
    with pytest.raises(InvalidRequestError):
        make(deep)
    with pytest.raises(InvalidRequestError):
        make({"blob": "x" * 5000}, max_argument_bytes=1024)


def test_rejects_unknown_operation_and_bad_names():
    with pytest.raises(InvalidRequestError):
        make(operation="sampling/createMessage")
    with pytest.raises(InvalidRequestError):
        make(tool="")


def test_arguments_property_returns_a_copy():
    req = make({"a": {"b": 1}})
    req.arguments["a"]["b"] = 99
    assert req.arguments == {"a": {"b": 1}}


def test_verify_integrity_detects_tampering():
    req = make({"path": "a.txt"})
    req.verify_integrity()
    forged = McpRequest(
        req.operation, req.client_id, req.tenant_id, req.user_id, req.server, req.tool,
        canonical_json({"path": "/etc/passwd"}), req.request_hash,
    )  # fmt: skip
    with pytest.raises(IntegrityError):
        forged.verify_integrity()
    with pytest.raises(IntegrityError):
        req.verify_integrity(expected_hash="0" * 64)


def test_frozen_request_cannot_be_mutated():
    req = make({"a": 1})
    with pytest.raises(AttributeError):
        req.tool = "other"  # type: ignore[misc]


def test_state_machine_terminal_states_have_no_exit():
    for status, nxt in ALLOWED_TRANSITIONS.items():
        assert status.is_terminal == (not nxt)
    for terminal in [s for s in RequestStatus if s.is_terminal]:
        assert not any(can_transition(terminal, t) for t in RequestStatus)


def test_only_approved_can_start_executing():
    sources = [s for s in RequestStatus if can_transition(s, RequestStatus.EXECUTING)]
    assert sources == [RequestStatus.APPROVED]
    assert not can_transition(RequestStatus.PENDING_APPROVAL, RequestStatus.EXECUTING)
    assert not can_transition(RequestStatus.REJECTED, RequestStatus.APPROVED)
    assert not can_transition(RequestStatus.EXPIRED, RequestStatus.APPROVED)


def test_record_transition_enforced():
    rec = RequestRecord(request=make({}))
    rec.transition(RequestStatus.VALIDATED)
    with pytest.raises(InvalidTransitionError):
        rec.transition(RequestStatus.COMPLETED)
