# Demo video script (about 3.5 minutes)

Use a throwaway sandbox - the demo server only touches `demo-sandbox/`. Never use real files or credentials.

| Time | Show |
|---|---|
| 0:00 | What MCP Firewall is (README diagram) |
| 0:30 | `claude_desktop_config.json` with the `mcp-firewall` entry; `mcp-firewall check` |
| 1:00 | In Claude Desktop: "Use demo__create_file to create hello.txt ..." -> the popup appears on top of Claude |
| 1:40 | Click **Allow**; Claude reports `created hello.txt`; show the file |
| 2:10 | Ask Claude to create another file; click **Block**; Claude reports `BLOCKED by the user` |
| 2:40 | Show `demo-output/exec-log.jsonl`: the blocked call is absent |
| 3:10 | `mcp-firewall audit tail` and `audit verify` (request states, hash chain OK) |
| optional | Ask Claude for 3 files at once: three independent popups, decide each differently |

Tip: `python scripts/demo.py` replays approve / block / timeout / policy-deny in one terminal.
