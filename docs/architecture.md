# Architecture

## Approach: a protocol-aware gateway, not a sniffer

MCP runs over STDIO pipes (Desktop) or TLS (Web), so passive monitoring cannot see - let alone *pause* - a call.
The reliable design is to be the MCP endpoint: Claude connects to the firewall; the firewall connects onward.
It therefore sees every request in clear, can hold it, and can answer with a protocol-correct error.
Built on the official MCP Python SDK (`mcp` 1.x low-level `Server` / `ClientSession`).

## Layers (dependency inversion)

```
interfaces ──> application ──> domain
     │              ▲
     └─> infrastructure (implements application ports)
```

* **domain** - `McpRequest` (frozen, canonical JSON + SHA-256 hash), `RequestRecord`, the status state machine
  (`RECEIVED → VALIDATED → PENDING_APPROVAL → APPROVED|REJECTED|EXPIRED|CANCELLED → EXECUTING → COMPLETED|FAILED|EXECUTION_UNKNOWN`, plus `DENIED`).
* **application** - `InterceptionService` (workflow), `PolicyEngine`, `ApprovalService`, `ExecutionService`,
  `AuditService`; ports: repositories, `EventBus`, `UpstreamGateway`, `Sanitizer`, `MetricsPort`.
  Imports no FastAPI / PySide6 / Redis / SQL.
* **infrastructure** - `UpstreamManager` (MCP client), `FirewallMcpServer` (MCP server), STDIO and HTTP proxies,
  SQL repositories (SQLite & PostgreSQL), in-memory & Redis event buses, sanitizer, auth, SSRF guard, secret box.
* **interfaces** - FastAPI approval API (REST + WebSocket + `/dashboard`), PySide6 agent (`AgentCore` is Qt-free).

`bootstrap.py` is the composition root.

## Request flow

1. `tools/call` arrives -> request frozen, canonicalised, hashed, size/shape validated.
2. **Persisted** (`RECEIVED`) *before* anything is shown to a human; audit event written.
3. Kill switch, upstream input-schema validation, tool-fingerprint change check.
4. Policy -> `allow` / `deny` / `require_approval` (+ advisory risk assessment).
5. Approval: `PENDING_APPROVAL` row + event; per-request `asyncio.Future` waits (also polls the DB, so
   lost events / other workers are covered). Progress notifications keep the client from timing out.
6. Decision: `UPDATE ... WHERE id=? AND status='PENDING_APPROVAL' AND expires_at > now` - exactly one wins.
7. Before dispatch the hash is **recomputed** and compared; only then `APPROVED → EXECUTING` (again atomic) and the
   exact frozen arguments go upstream. Outcome recorded; response returned with the original request correlation
   (the SDK keeps the JSON-RPC id mapping; each call has its own coroutine).

## Concurrency

No global flags. Each request has its own id, deadline, future, DB row and decision. Bounded pending queue,
per-upstream semaphores, cancellation propagation (client disconnect → `CANCELLED`), a reaper that expires
abandoned requests and marks stuck executions `EXECUTION_UNKNOWN` (never auto-retried), duplicate-event
suppression and `resync` for slow subscribers.

## Deployment shapes

* **Local**: Claude Desktop spawns `mcp-firewall stdio`; SQLite; embedded loopback-only approval API on an
  ephemeral port with a per-process token published (owner-only file) for the tray agent; the agent is
  auto-launched.
* **Remote**: `mcp-firewall serve` (FastAPI + Streamable HTTP, stateless sessions), PostgreSQL (state, audit),
  Redis (cross-worker events), Docker Compose. Modular monolith - extract services only when load requires.

## Decisions & trade-offs

* Used the stable `mcp` 1.x SDK (2.x has a different API).
* The Next.js dashboard was replaced by one dependency-free page (`textContent` only, strict CSP) to keep the
  surface small; the REST/WS API is the stable contract for a richer UI.
* SQLite locally, PostgreSQL remotely, one SQL repository for both.
