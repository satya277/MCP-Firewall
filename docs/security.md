# Security model

## Assumptions / threats considered

The upstream MCP servers, tool names/descriptions and tool arguments are **untrusted**. The user's machine is
trusted; other local users and the network are not. A compromised model may try to run destructive tools,
smuggle arguments, or spoof an approval.

## Controls

| Threat | Control | Test |
|---|---|---|
| Executing without approval | state machine + atomic CAS; only `APPROVED → EXECUTING` | `test_pipeline`, e2e |
| Approving a different request than shown (TOCTOU) | SHA-256 over canonical {operation, client, server, tool, args}; decision carries the hash; recomputed before dispatch | `test_arguments_tampered_...` |
| Duplicate / replayed / late / forged decisions | single-use atomic transition, expiry in the SQL `WHERE`, hash binding, role + tenant checks | `test_replay_and_hash_forgery_rejected`, storm tests |
| Spoofed approvals | bearer tokens (SHA-256 hashes configured, constant-time compare), roles viewer/approver/admin, throttled failures, Host + Origin checks, loopback-only local API | `test_api_security` |
| UI crash / closed popup = approval? | never; window close/Esc only hides; timeout = block | `test_desktop_ui` |
| Infra down | fail closed: DB/Redis errors → request denied, never executed | pipeline tests |
| Rug-pull (tool definition changes) | fingerprint per tool, change forces approval with a warning (cannot override deny) | `test_tool_schema_change_...` |
| Prompt injection in metadata | descriptions displayed as plain text only; never parsed; policy is code/YAML | `test_prompt_injection_...` |
| Secret leakage | redaction in UI, logs, audit; arguments encrypted at rest (Fernet; env / keyring / key file) | `test_secrets_do_not_leak_...` |
| Command injection via upstream config | executable allowlist, argument arrays, no shell | `test_executable_allowlist_...` |
| SSRF via remote upstream | https only, public addresses only unless allow-listed, no redirects, no URL credentials | `test_ssrf_*` |
| Audit tampering | append-only (DB triggers) + SHA-256 hash chain, `audit verify` | `test_audit_chain_...` |
| Resource exhaustion | size/depth limits, bounded pending queue, rate limits, body caps, WS message caps | concurrency/security tests |
| Rogue web page → dashboard | no CORS, Origin check, CSP, `textContent` rendering, token in sessionStorage | `test_dashboard_never_uses_unsafe_html_sinks` |

## Known limitations (be aware)

* Anything not routed through the firewall is not protected.
* A local process running as the same OS user can read the gateway discovery file (owner-only permissions, but
  same user) and approve via the loopback API. This is inherent to same-user trust.
* Risk labels are heuristic hints; **enforcement is the YAML policy only**.
* `EXECUTION_UNKNOWN` is reported honestly; non-idempotent operations are never retried.
* Claude Web needs a publicly reachable HTTPS endpoint; TLS is terminated by your proxy. The capability-URL
  fallback leaks via logs if you are careless - prefer the bearer token.
* The Redis bus is best-effort pub/sub; durability comes from PostgreSQL + the polling reconciliation.
