"""Command line interface: ``mcp-firewall <command>``."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from mcp_firewall.config import Settings, load_policy_file, load_servers
from mcp_firewall.observability.logging import configure_logging


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings()
    if getattr(args, "servers", None):
        settings.servers_file = Path(args.servers)
    if getattr(args, "policies", None):
        settings.policies_file = Path(args.policies)
    return settings


def _add_config_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--servers", help="servers YAML (default: $MCPFW_SERVERS_FILE)")
    p.add_argument("--policies", help="policies YAML (default: $MCPFW_POLICIES_FILE)")


def cmd_stdio(args: argparse.Namespace) -> int:
    from mcp_firewall.infrastructure.mcp.stdio_proxy import run_stdio_gateway

    settings = _settings(args)
    configure_logging(settings.log_level, settings.log_json)  # stderr only: stdout is the MCP channel
    try:
        asyncio.run(run_stdio_gateway(settings, settings.servers_file, settings.policies_file))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from mcp_firewall.infrastructure.mcp.http_proxy import create_remote_app

    settings = _settings(args)
    configure_logging(settings.log_level, settings.log_json)
    app = create_remote_app(settings, settings.servers_file, settings.policies_file)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        log_config=None,
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips=args.forwarded_allow_ips,
        timeout_keep_alive=65,
    )
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    try:
        from mcp_firewall.interfaces.desktop.agent import run_agent
    except ImportError as exc:
        print(
            f"The desktop agent needs PySide6: pip install 'mcp-firewall[desktop]' ({exc})", file=sys.stderr
        )
        return 2
    settings = Settings()
    configure_logging(settings.log_level, settings.log_json)
    return run_agent(
        settings, remotes_file=Path(args.remotes) if args.remotes else None, headless=args.headless
    )


def cmd_token(args: argparse.Namespace) -> int:
    from mcp_firewall.infrastructure.security.authentication import generate_token, hash_token

    if args.action == "generate":
        token = generate_token()
        print(f"token  : {token}   (give this to the client/approver; shown only once)")
        print(f"sha256 : {hash_token(token)}")
        print("\nAdd to .env, e.g.:")
        print(f"  MCPFW_APPROVER_TOKENS=alice:admin:{hash_token(token)}")
        print(f"  MCPFW_MCP_CLIENT_TOKENS=claude-web:{hash_token(token)}")
    else:
        print(hash_token(args.value))
    return 0


async def _audit(args: argparse.Namespace) -> int:
    from mcp_firewall.bootstrap import make_database
    from mcp_firewall.infrastructure.persistence.repositories.sql_audit import SqlAuditLog

    db = make_database(Settings())
    await db.start()
    try:
        log = SqlAuditLog(db)
        if args.action == "verify":
            ok, checked, error = await log.verify_chain()
            print(json.dumps({"ok": ok, "events_checked": checked, "error": error}))
            return 0 if ok else 1
        events = await log.list_events(limit=1000)
        for e in events[-args.limit :]:
            print(
                f"{e.seq:>5} {e.event_type:<28} actor={e.actor_id:<18} req={e.request_id or '-'} {json.dumps(e.metadata)}"
            )
        return 0
    finally:
        await db.stop()


def cmd_audit(args: argparse.Namespace) -> int:
    return asyncio.run(_audit(args))


def cmd_check(args: argparse.Namespace) -> int:
    settings = _settings(args)
    servers = load_servers(settings.servers_file)
    policy = load_policy_file(settings.policies_file)
    print(f"servers : {[s.name for s in servers.servers]}")
    print(
        f"policy  : version {policy.version}, {len(policy.rules)} rules, default={policy.default_action.value}"
    )
    return 0


def cmd_claude_config(args: argparse.Namespace) -> int:
    servers = str(Path(args.servers or "config/servers.yaml").resolve())
    policies = str(Path(args.policies or "config/policies.yaml").resolve())
    entry = {
        "mcpServers": {
            "mcp-firewall": {
                "command": sys.executable,
                "args": ["-m", "mcp_firewall", "stdio", "--servers", servers, "--policies", policies],
            }
        }
    }
    print(json.dumps(entry, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-firewall", description="Human-in-the-loop MCP security gateway"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("stdio", help="run the local STDIO gateway (Claude Desktop launches this)")
    _add_config_args(p)
    p.set_defaults(func=cmd_stdio)

    p = sub.add_parser("serve", help="run the remote Streamable-HTTP gateway (Claude Web)")
    _add_config_args(p)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--forwarded-allow-ips", default="127.0.0.1", help="trusted reverse-proxy addresses")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("agent", help="run the desktop approval agent (tray + popups)")
    p.add_argument("--remotes", help="YAML listing remote gateways to connect to")
    p.add_argument("--headless", action="store_true", help="no UI (diagnostics / tests)")
    p.set_defaults(func=cmd_agent)

    p = sub.add_parser("token", help="generate or hash access tokens")
    p.add_argument("action", choices=["generate", "hash"])
    p.add_argument("value", nargs="?")
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("audit", help="inspect or verify the tamper-evident audit log")
    p.add_argument("action", choices=["verify", "tail"])
    p.add_argument("-n", "--limit", type=int, default=50)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("check", help="validate the servers and policy files")
    _add_config_args(p)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("claude-config", help="print the claude_desktop_config.json entry")
    _add_config_args(p)
    p.set_defaults(func=cmd_claude_config)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "token" and args.action == "hash" and not args.value:
        print("usage: mcp-firewall token hash <token>", file=sys.stderr)
        return 2
    try:
        return args.func(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
