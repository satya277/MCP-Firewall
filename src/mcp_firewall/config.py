"""Configuration: environment settings, upstream server definitions and policy file loading."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from mcp_firewall.application.services.policy_service import KNOWN_OPERATORS
from mcp_firewall.domain.entities.policy import Condition, PolicyRule, PolicySet
from mcp_firewall.domain.enums.decision import PolicyAction, RiskLevel

DEFAULT_EXECUTABLES = [
    "python", "python3", "python.exe", "py", "node", "node.exe", "npx", "npx.cmd", "uv", "uvx", "uv.exe",
    "uvx.exe", "deno", "bun",
]  # fmt: skip
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="MCPFW_", env_file=".env", extra="ignore")

    home: Path = Field(default_factory=lambda: Path.home() / ".mcp-firewall")
    servers_file: Path = Path("config/servers.yaml")
    policies_file: Path = Path("config/policies.yaml")

    approval_timeout_seconds: float = Field(60.0, gt=1, le=3600)
    max_pending_requests: int = Field(100, ge=1, le=10_000)
    max_argument_bytes: int = Field(262_144, ge=1_024, le=10_485_760)
    execution_timeout_seconds: float = Field(120.0, gt=1, le=3600)
    max_concurrent_per_server: int = Field(8, ge=1, le=256)
    sweep_interval_seconds: float = Field(5.0, gt=0.1)

    database_url: str | None = None
    redis_url: str | None = None
    encryption_key: str | None = None

    tenant_id: str = "default"
    client_id: str = "claude-desktop"
    approver_tokens: str = ""
    mcp_client_tokens: str = ""
    mcp_path_secret: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)  # Host headers accepted by the HTTP gateway
    allowed_origins: list[str] = Field(default_factory=list)  # Origins permitted for browser dashboards

    auto_start_agent: bool = True
    log_level: str = "INFO"
    log_json: bool = False

    @property
    def run_dir(self) -> Path:
        return self.home / "run"

    @property
    def sqlite_path(self) -> Path:
        return self.home / "firewall.db"


class ServerConfig(BaseModel):
    name: str
    transport: Literal["stdio", "streamable_http"] = "stdio"
    enabled: bool = True
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str | None = None
    url: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    connect_timeout_seconds: float = 30.0
    allowed_hosts: list[str] = Field(default_factory=list)
    allow_insecure_loopback: bool = False

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not _NAME.match(v):
            raise ValueError("server name must match [A-Za-z0-9_-]{1,32}")
        return v

    @model_validator(mode="after")
    def _check(self) -> ServerConfig:
        if self.transport == "stdio" and not self.command:
            raise ValueError(f"server {self.name!r}: stdio transport requires 'command'")
        if self.transport == "streamable_http" and not self.url:
            raise ValueError(f"server {self.name!r}: streamable_http transport requires 'url'")
        return self


class ServersConfig(BaseModel):
    servers: list[ServerConfig]
    namespace_tools: bool = True
    allowed_executables: list[str] = Field(default_factory=lambda: list(DEFAULT_EXECUTABLES))

    @model_validator(mode="after")
    def _check(self) -> ServersConfig:
        names = [s.name for s in self.servers]
        if len(set(names)) != len(names):
            raise ValueError("duplicate server names")
        if not self.namespace_tools and len([s for s in self.servers if s.enabled]) > 1:
            raise ValueError("namespace_tools=false is only allowed with a single enabled server")
        return self


def load_servers(path: Path) -> ServersConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return ServersConfig.model_validate(data)


def _as_tuple(value: Any, default: tuple[str, ...] = ("*",)) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


def parse_policy(data: dict[str, Any]) -> PolicySet:
    default = PolicyAction(data.get("default_action", "require_approval"))
    rules: list[PolicyRule] = []
    seen: set[str] = set()
    for raw in data.get("rules", []) or []:
        rid = str(raw["id"])
        if rid in seen:
            raise ValueError(f"duplicate policy rule id: {rid}")
        seen.add(rid)
        conditions = []
        for cond in raw.get("when", []) or []:
            op = str(cond["op"])
            if op not in KNOWN_OPERATORS:
                raise ValueError(f"rule {rid}: unknown operator {op!r}")
            conditions.append(Condition(path=str(cond["path"]), op=op, value=cond.get("value")))
        risk = raw.get("risk")
        rules.append(
            PolicyRule(
                id=rid,
                action=PolicyAction(raw["action"]),
                priority=int(raw.get("priority", 0)),
                description=str(raw.get("description", "")),
                servers=_as_tuple(raw.get("servers")),
                tools=_as_tuple(raw.get("tools")),
                clients=_as_tuple(raw.get("clients")),
                operations=_as_tuple(raw.get("operations")),
                conditions=tuple(conditions),
                risk=RiskLevel[str(risk).upper()] if risk else None,
                strong_confirmation=bool(raw.get("strong_confirmation", False)),
                approver_role=str(raw.get("approver_role", "approver")),
                enabled=bool(raw.get("enabled", True)),
            )
        )
    canonical = json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))
    version = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return PolicySet(version=version, rules=tuple(rules), default_action=default)


def load_policy_file(path: Path) -> PolicySet:
    return parse_policy(yaml.safe_load(path.read_text(encoding="utf-8")) or {})
