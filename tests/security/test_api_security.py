"""Security tests against the live approval API (real uvicorn server on loopback)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
import websockets

from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.infrastructure.mcp.stdio_proxy import start_local_api
from mcp_firewall.interfaces.api.auth import reset_auth_throttle
from mcp_firewall.interfaces.api.routes.approvals import reset_decision_limiter
from mcp_firewall.interfaces.api.websocket import ConnectionRegistry
from tests.conftest import make_container
from tests.integration.test_pipeline import incoming, wait_for_pending

ADMIN_TOKEN = "admin-token-for-tests-0123456789"
APPROVER_TOKEN = "approver-token-for-tests-0123456789"
VIEWER_TOKEN = "viewer-token-for-tests-0123456789"


@pytest.fixture
async def live(tmp_path):
    reset_auth_throttle()
    reset_decision_limiter()
    container, upstream = await make_container(tmp_path)
    container.approver_auth.add(Principal("viewer", Role.VIEWER), VIEWER_TOKEN)
    container.approver_auth.add(Principal("alice", Role.APPROVER), APPROVER_TOKEN)
    registry = ConnectionRegistry()
    server, task, port = await start_local_api(container, registry, ADMIN_TOKEN)
    base = f"http://127.0.0.1:{port}"
    try:
        yield container, upstream, base, port, registry
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 5)
        await container.stop()
        reset_auth_throttle()


def hdr(token):
    return {"Authorization": f"Bearer {token}"}


async def start_request(container, tool="create_file", args=None):
    task = asyncio.create_task(container.interception.intercept(incoming(tool, args or {"path": "a.txt"})))
    (rec,) = await wait_for_pending(container)
    return task, rec


async def test_unauthenticated_and_bad_tokens_rejected(live):
    container, _, base, *_ = live
    async with httpx.AsyncClient(base_url=base) as c:
        for path in ("/api/v1/requests", "/api/v1/status", "/api/v1/audit", "/metrics", "/api/v1/policy"):
            assert (await c.get(path)).status_code == 401
            assert (await c.get(path, headers=hdr("wrong"))).status_code == 401
        assert (await c.get("/healthz")).status_code == 200  # liveness is public and leaks nothing
        assert (await c.get("/healthz")).json() == {"status": "ok"}


async def test_decision_endpoint_requires_approver_role(live):
    container, upstream, base, *_ = live
    task, rec = await start_request(container)
    body = {"decision": "allow", "request_hash": rec.request.request_hash}
    async with httpx.AsyncClient(base_url=base) as c:
        url = f"/api/v1/requests/{rec.id}/decision"
        assert (await c.post(url, json=body)).status_code == 401
        assert (await c.post(url, json=body, headers=hdr(VIEWER_TOKEN))).status_code == 403
        assert upstream.executed == []
        r = await c.post(url, json=body, headers=hdr(APPROVER_TOKEN))
        assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    assert (await task).status.value == "COMPLETED"


async def test_replay_and_hash_forgery_rejected(live):
    container, upstream, base, *_ = live
    task, rec = await start_request(container)
    url = f"/api/v1/requests/{rec.id}/decision"
    async with httpx.AsyncClient(base_url=base) as c:
        forged = await c.post(
            url, json={"decision": "allow", "request_hash": "a" * 64}, headers=hdr(APPROVER_TOKEN)
        )
        assert forged.status_code == 409 and forged.json()["error"] == "hash_mismatch"
        malformed = await c.post(
            url, json={"decision": "allow", "request_hash": "zz"}, headers=hdr(APPROVER_TOKEN)
        )
        assert malformed.status_code == 422
        bad_verb = await c.post(
            url,
            json={"decision": "maybe", "request_hash": rec.request.request_hash},
            headers=hdr(APPROVER_TOKEN),
        )
        assert bad_verb.status_code == 422
        ok = {"decision": "block", "request_hash": rec.request.request_hash}
        assert (await c.post(url, json=ok, headers=hdr(APPROVER_TOKEN))).status_code == 200
        replay = await c.post(
            url,
            json={"decision": "allow", "request_hash": rec.request.request_hash},
            headers=hdr(APPROVER_TOKEN),
        )
        assert replay.status_code == 409 and replay.json()["error"] == "already_decided"
        unknown = await c.post("/api/v1/requests/nope/decision", json=ok, headers=hdr(APPROVER_TOKEN))
        assert unknown.status_code == 404
    assert (await task).status.value == "REJECTED" and upstream.executed == []
    events = await container.audit_log.list_events(request_id=rec.id)
    assert sum(e.event_type == "approval.attempt_rejected" for e in events) >= 2


async def test_strong_confirmation_enforced_server_side(live):
    container, upstream, base, *_ = live
    task, rec = await start_request(container, "delete_file", {"path": "x"})
    url = f"/api/v1/requests/{rec.id}/decision"
    body = {"decision": "allow", "request_hash": rec.request.request_hash}
    async with httpx.AsyncClient(base_url=base) as c:
        r = await c.post(url, json=body, headers=hdr(APPROVER_TOKEN))
        assert r.status_code == 428 and upstream.executed == []
        assert (
            await c.post(url, json={**body, "confirm": True}, headers=hdr(APPROVER_TOKEN))
        ).status_code == 200
    await task


async def test_brute_force_lockout(live):
    _, _, base, *_ = live
    async with httpx.AsyncClient(base_url=base) as c:
        codes = [(await c.get("/api/v1/me", headers=hdr(f"guess-{i}"))).status_code for i in range(20)]
        assert 429 in codes
        # even the correct token is refused while locked out
        assert (await c.get("/api/v1/me", headers=hdr(ADMIN_TOKEN))).status_code == 429


async def test_host_header_and_origin_protection(live):
    _, _, base, port, _ = live
    async with httpx.AsyncClient(base_url=base) as c:
        evil_host = await c.get(
            "/api/v1/me", headers={**hdr(ADMIN_TOKEN), "Host": f"evil.example.com:{port}"}
        )
        assert evil_host.status_code == 400  # DNS-rebinding style request
        evil_origin = await c.post(
            "/api/v1/killswitch",
            json={"enabled": True},
            headers={**hdr(ADMIN_TOKEN), "Origin": "https://evil.example.com"},
        )
        assert evil_origin.status_code == 403
        assert (await c.get("/api/v1/killswitch", headers=hdr(ADMIN_TOKEN))).json() == {"enabled": False}


async def test_oversized_body_rejected(live):
    _, _, base, *_ = live
    async with httpx.AsyncClient(base_url=base) as c:
        r = await c.post(
            "/api/v1/killswitch",
            content=b"x" * 200_000,
            headers={**hdr(ADMIN_TOKEN), "Content-Type": "application/json"},
        )
        assert r.status_code == 413


async def test_admin_only_endpoints(live):
    container, _, base, *_ = live
    async with httpx.AsyncClient(base_url=base) as c:
        for token in (VIEWER_TOKEN, APPROVER_TOKEN):
            assert (
                await c.post("/api/v1/killswitch", json={"enabled": True}, headers=hdr(token))
            ).status_code == 403
            assert (await c.get("/api/v1/audit/verify", headers=hdr(token))).status_code == 403
            assert (await c.post("/api/v1/policy/reload", headers=hdr(token))).status_code == 403
        assert (
            await c.post("/api/v1/killswitch", json={"enabled": True}, headers=hdr(ADMIN_TOKEN))
        ).status_code == 200
        assert (await container.interception.is_kill_switch_on()) is True
        assert (await c.get("/api/v1/audit/verify", headers=hdr(ADMIN_TOKEN))).json()["ok"] is True


async def test_security_headers_and_no_stacktrace_leak(live):
    _, _, base, *_ = live
    async with httpx.AsyncClient(base_url=base) as c:
        r = await c.get("/dashboard")
        assert r.status_code == 200
        assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["cache-control"] == "no-store"


def test_dashboard_never_uses_unsafe_html_sinks():
    from mcp_firewall.interfaces.api.app import STATIC

    html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "eval("):
        assert sink not in html


# --- websocket ---------------------------------------------------------------------------------------


async def ws_connect(port, **kw):
    return await websockets.connect(f"ws://127.0.0.1:{port}/api/v1/ws", **kw)


async def test_ws_requires_auth_first_message(live):
    _, _, _, port, registry = live
    ws = await ws_connect(port)
    await ws.send(json.dumps({"type": "refresh"}))  # not an auth message
    assert json.loads(await asyncio.wait_for(ws.recv(), 3)) == {"type": "error", "error": "unauthorized"}
    with pytest.raises(websockets.ConnectionClosed):
        await asyncio.wait_for(ws.recv(), 3)
    ws = await ws_connect(port)
    await ws.send(json.dumps({"type": "auth", "token": "wrong"}))
    first = json.loads(await asyncio.wait_for(ws.recv(), 3))
    assert first == {"type": "error", "error": "unauthorized"}
    assert registry.count() == 0
    # silence: never authenticating at all is also closed (auth timeout)


async def test_ws_rejects_foreign_origin(live):
    _, _, _, port, _ = live
    with pytest.raises(websockets.InvalidStatus):
        ws = await ws_connect(port, additional_headers={"Origin": "https://evil.example.com"})
        await ws.recv()


async def test_ws_streams_prompts_to_authenticated_approvers_only(live):
    container, upstream, _, port, registry = live
    ws = await ws_connect(port)
    await ws.send(json.dumps({"type": "auth", "token": APPROVER_TOKEN}))
    assert json.loads(await ws.recv())["type"] == "ready"
    assert json.loads(await ws.recv()) == {"type": "snapshot", "pending": []}
    assert registry.count() == 1
    task, rec = await start_request(container, "create_file", {"path": "p", "password": "s3cr3t"})
    msg = None
    for _ in range(5):
        m = json.loads(await asyncio.wait_for(ws.recv(), 3))
        if m["type"] == "event" and m["event"]["type"] == "approval.requested":
            msg = m["event"]["payload"]
            break
    assert msg and msg["id"] == rec.id and msg["request_hash"] == rec.request.request_hash
    assert "s3cr3t" not in msg["arguments"]  # secrets never cross the wire
    await container.reject(Principal("alice", Role.APPROVER), rec.id, rec.request.request_hash)
    await task
    await ws.close()
    await asyncio.sleep(0.3)
    assert registry.count() == 0


async def test_ws_new_client_gets_snapshot_of_pending(live):
    container, _, _, port, _ = live
    task, rec = await start_request(container)
    ws = await ws_connect(port)
    await ws.send(json.dumps({"type": "auth", "token": VIEWER_TOKEN}))
    await ws.recv()
    snap = json.loads(await ws.recv())
    assert [r["id"] for r in snap["pending"]] == [rec.id]
    await container.reject(Principal("alice", Role.APPROVER), rec.id, rec.request.request_hash)
    await task
    await ws.close()


async def test_viewer_ws_not_counted_as_available_approver(live):
    _, _, _, port, registry = live
    ws = await ws_connect(port)
    await ws.send(json.dumps({"type": "auth", "token": VIEWER_TOKEN}))
    await ws.recv()
    assert registry.count() == 0
    await ws.close()
