# MCP Firewall

A **human-in-the-loop security gateway for the Model Context Protocol (MCP)**. It sits between an AI client
(Claude Desktop, Claude Web) and its MCP servers, holds every tool call until a person clicks
**Allow** or **Block**, and only ever forwards the exact request the person approved.

![Approval dialog](docs/images/approval-dialog.png)

## How it works (one paragraph)

MCP traffic is not something you can sniff reliably (it's local pipes or TLS). So this project is a
**protocol-aware gateway**: Claude is configured to use the firewall as its MCP server; the firewall acts as
an MCP *server* towards Claude and an MCP *client* towards your real MCP servers. Each `tools/call` is
frozen and hashed, checked against a deterministic policy, persisted, and - if it needs approval - shown in an
always-on-top desktop popup. The call waits (with progress keep-alives) until you decide; **Block / timeout /
crash = never executed**, and Claude receives a clear denial message. Details: [docs/architecture.md](docs/architecture.md),
[docs/security.md](docs/security.md), [docs/sequence-diagrams.md](docs/sequence-diagrams.md).

## Architecture diagram

```mermaid
flowchart LR
    subgraph Clients
      CD["Claude Desktop"]
      CW["Claude Web (cloud)"]
    end
    subgraph FW["MCP Firewall"]
      direction TB
      GW["Gateway<br/>validate, hash, persist"]
      POL["Policy engine<br/>allow / deny / ask"]
      APR["Approval manager<br/>one decision per request"]
      EXE["Executor<br/>re-verify hash, forward exact args"]
      GW --> POL --> APR --> EXE
    end
    UI["Desktop agent<br/>tray + topmost popup<br/>Allow / Block"]
    DASH["Web dashboard /dashboard"]
    TOOLS["Real MCP tools<br/>(servers.local.yaml)"]
    DB[("SQLite / PostgreSQL<br/>requests + audit log")]

    CD -- "stdio" --> GW
    CW -- "HTTPS /mcp" --> GW
    APR <-- "loopback / WebSocket" --> UI
    APR <-- "authenticated" --> DASH
    EXE -- "only if approved" --> TOOLS
    FW --- DB
```

Rendered diagram (always visible, even where Mermaid is not supported):

![MCP Firewall architecture](docs/images/architecture.png)

Text version:

```
Claude Desktop --stdio--> [ MCP Firewall (local) ] --stdio/https--> real MCP servers
                              |  policy + hash + audit
                              +--(loopback, token)--> Desktop agent: tray + topmost popup

Claude Web --https--> [ MCP Firewall (remote, Docker) ] ---> real MCP servers
                              +--(authenticated WebSocket)--> Desktop agent / /dashboard
```

## Compatibility - read this first

| Client | Supported how | Status |
|---|---|---|
| **Claude Desktop** (local MCP servers) | Firewall registered as the MCP server in `claude_desktop_config.json` | **Verified end-to-end on a real Claude Desktop** (approve, block, high-risk delete) |
| **Claude Web** (claude.ai) | Remote custom connector -> the HTTPS gateway (`mcp-firewall serve`) | Gateway + auth + approvals covered by automated end-to-end tests using a real Streamable-HTTP MCP client. **Not tested against the live claude.ai connector** (needs a public HTTPS URL and a plan with custom connectors). |
| Any other MCP client | Same transports | Works the same way |

Honest limitations:

* The firewall controls only servers **routed through it**. A server left configured directly in Claude is not
  intercepted - move those entries into `servers.yaml`.
* Claude Web's calls originate from Anthropic's cloud, so they can never reach a local STDIO process. For Web you
  deploy the HTTPS gateway; the popup then comes from the desktop agent connected to that gateway
  (`--remotes`), or from the built-in `/dashboard`.
* Claude Desktop's own built-in tools / extensions do not go through MCP config and are out of scope.

## Install

Requires **Python 3.12+** (developed on 3.14). Windows, macOS and Linux.

```bash
git clone <this repo> && cd <repo>
python -m venv .venv
.venv\Scripts\activate            # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -e ".[desktop,dev]"   # add ,postgres,redis for the remote deployment
```

## Quick start (no Claude needed)

```bash
python scripts/demo.py            # real popup: click Allow on #1, Block on #2, ignore #3
python scripts/demo.py --auto     # answers by itself (dry run / CI)
```

It runs the sandboxed demo MCP server (`read_file`, `create_file`, `delete_file`, `echo`) and prints the
upstream's own **execution log**, which proves blocked/expired calls never ran.

## Use with Claude Desktop

1. Copy and edit the config (use absolute paths: Claude's working directory is unpredictable):

   ```bash
   copy config\servers.example.yaml config\servers.local.yaml
   copy config\policies.example.yaml config\policies.local.yaml
   mcp-firewall check --servers config\servers.local.yaml --policies config\policies.local.yaml
   ```

2. Print the Claude Desktop entry and paste it into `%APPDATA%\Claude\claude_desktop_config.json`
   (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`), under `"mcpServers"`:

   ```bash
   mcp-firewall claude-config --servers config\servers.local.yaml --policies config\policies.local.yaml
   ```

   ```json
   { "mcpServers": { "mcp-firewall": {
       "command": "C:\\path\\to\\.venv\\Scripts\\python.exe",
       "args": ["-m", "mcp_firewall", "stdio", "--servers", "C:\\path\\config\\servers.local.yaml",
                "--policies", "C:\\path\\config\\policies.local.yaml"] } } }
   ```

3. **Fully quit and restart Claude Desktop** (tray icon -> Quit). The tools appear as `demo__create_file`, etc.
4. The first time a call needs approval the firewall **auto-starts the tray agent** (`MCPFW_AUTO_START_AGENT=true`)
   and the popup appears. You can also run it yourself: `mcp-firewall agent`.

Move your *other* MCP servers from Claude's config into `servers.local.yaml`, otherwise they bypass the firewall.

## Use with Claude Web (remote gateway)

```bash
mcp-firewall token generate        # run twice: one MCP-client token, one approver token
cp .env.example .env               # fill MCPFW_MCP_CLIENT_TOKENS, MCPFW_APPROVER_TOKENS (hashes only),
                                   # MCPFW_ENCRYPTION_KEY, POSTGRES_PASSWORD
docker compose up --build          # gateway + PostgreSQL + Redis on 127.0.0.1:8080
```

Put a TLS terminator in front (reverse proxy, Cloudflare/ngrok tunnel...), then in claude.ai add a custom
connector pointing at `https://<your-host>/mcp`. Connectors that cannot send an `Authorization` header can use
the capability URL `https://<your-host>/mcp/<MCPFW_MCP_PATH_SECRET>` (treat it like a password). Approve either in
the browser at `https://<your-host>/dashboard` (paste an approver token) or with the desktop agent:

```bash
copy config\remotes.example.yaml config\remotes.yaml     # url + ${MCPFW_REMOTE_APPROVER_TOKEN}
mcp-firewall agent --remotes config\remotes.yaml
```

The server refuses to start without client tokens/secret **and** approver tokens.

## Policies

`config/policies.example.yaml`. Deterministic rules: selectors (server/tool/client/operation globs), argument
conditions (`equals`, `starts_with`, `regex`, `glob`, `path_within`, `in`, numeric comparisons, `exists`...),
priority, `strong_confirmation`, `approver_role`. Resolution: **any matching `deny` wins**; else highest priority
(tie -> most restrictive); no match -> `default_action` (`require_approval`). Reload without restart via
`POST /api/v1/policy/reload` (admin); an invalid file leaves the old policy active.
Tool descriptions are shown to you but never influence decisions.

## Configuration

Environment variables (`MCPFW_*`, or `.env`) - see [.env.example](.env.example): approval timeout (default 60 s),
pending-queue bound, argument size limit, execution timeout, `DATABASE_URL` (SQLite by default, PostgreSQL for
remote), `REDIS_URL`, token hashes, encryption key.

## Command line

| Command | Purpose |
|---|---|
| `mcp-firewall stdio` | local gateway (what Claude Desktop launches) |
| `mcp-firewall serve` | remote Streamable-HTTP gateway |
| `mcp-firewall agent` | tray app + popups (`--remotes`, `--headless`) |
| `mcp-firewall token generate\|hash` | create tokens / hash them for config |
| `mcp-firewall audit tail\|verify` | read the audit log / verify its hash chain |
| `mcp-firewall check` / `claude-config` | validate configs / print the Claude Desktop entry |

## Tests

```bash
pytest                                  # 190+ tests: unit, integration, security, concurrency, e2e, UI (offscreen Qt)
docker run -d -p 54329:5432 -e POSTGRES_USER=mcpfw -e POSTGRES_PASSWORD=testpw -e POSTGRES_DB=mcpfw postgres:16-alpine
docker run -d -p 63799:6379 redis:7-alpine
set MCPFW_TEST_POSTGRES_URL=postgresql://mcpfw:testpw@localhost:54329/mcpfw    # enables the PostgreSQL tests
set MCPFW_TEST_REDIS_URL=redis://localhost:63799/0                              # real Redis instead of fakeredis
pytest
```

Highlights: 100 simultaneous requests with random decisions and no cross-talk; decision storms with exactly one
winner; TOCTOU tampering; forged/replayed/late decisions; brute-force lockout; SSRF; secret-leak canaries;
real STDIO and Streamable-HTTP end-to-end runs; the gateway auto-launching the real agent.

## Demo video

Record following [docs/demo-script.md](docs/demo-script.md) (Claude Desktop approve -> block -> audit view ->
execution log). The recording itself is not generated by this repo - add it (or a link) here.

## Troubleshooting

* *No tools in Claude after editing the config* - Claude must be **fully quit** (tray -> Quit), not just closed.
  Run `mcp-firewall check ...` first.
* *No popup* - run `mcp-firewall agent` manually; check the tray icon; a request not answered in 60 s is
  blocked (that is intentional). Windows may refuse focus-stealing: the dialog is still topmost and the tray
  balloon / taskbar flash fires as fallback.
* *"upstream is not connected"* - the command in `servers.local.yaml` failed; `executable ... not in
  allowed_executables` means add its base name to `allowed_executables`.
* *stdout corruption* - never print to stdout in code running inside the gateway; logs go to stderr.

## Layout

```
src/mcp_firewall/
  domain/          entities, state machine, canonical hashing   (no framework imports)
  application/     services, use cases, ports (interfaces)
  infrastructure/  MCP (stdio/http proxies, upstream manager), persistence (SQLite/PostgreSQL/Redis), security
  interfaces/      FastAPI approval API + dashboard, PySide6 desktop agent
  observability/   structlog, Prometheus, optional OpenTelemetry
tests/{unit,integration,security,concurrency,e2e}   config/   docs/   demo/   scripts/
```

Not built (future work): a Next.js dashboard (a dependency-free `/dashboard` page ships instead), OAuth for the
MCP endpoint (bearer / capability-URL auth ships), and a policy-administration UI.
