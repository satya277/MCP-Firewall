"""Composition root: wires adapters into the application services (dependency inversion)."""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

import structlog

from mcp_firewall.application.interfaces.event_publisher import EventBus
from mcp_firewall.application.interfaces.upstream import ApproverNotifier, NullNotifier
from mcp_firewall.application.services.approval_service import ApprovalService
from mcp_firewall.application.services.audit_service import AuditService
from mcp_firewall.application.services.execution_service import ExecutionService
from mcp_firewall.application.services.interception_service import (
    KILL_SWITCH_KEY,
    InterceptionConfig,
    InterceptionService,
)
from mcp_firewall.application.services.policy_service import PolicyEngine
from mcp_firewall.application.use_cases.approve_request import ApproveRequest
from mcp_firewall.application.use_cases.reject_request import RejectRequest
from mcp_firewall.config import Settings, load_policy_file
from mcp_firewall.domain.entities.audit import AuditEventType
from mcp_firewall.domain.entities.policy import PolicySet
from mcp_firewall.infrastructure.events.event_bus import InMemoryEventBus
from mcp_firewall.infrastructure.mcp.client_manager import UpstreamManager
from mcp_firewall.infrastructure.persistence.database import Database
from mcp_firewall.infrastructure.persistence.repositories.sql_audit import SqlAuditLog
from mcp_firewall.infrastructure.persistence.repositories.sql_repository import SqlRepository
from mcp_firewall.infrastructure.persistence.schema import ensure_schema
from mcp_firewall.infrastructure.persistence.sqlite import SqliteDatabase
from mcp_firewall.infrastructure.security.authentication import (
    TokenAuthenticator,
    parse_approver_tokens,
    parse_client_tokens,
)
from mcp_firewall.infrastructure.security.sanitizer import Sanitizer
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox, load_secret_box
from mcp_firewall.observability.metrics import PrometheusMetrics

log = structlog.get_logger("bootstrap")


def make_database(settings: Settings) -> Database:
    url = settings.database_url
    if url and url.startswith(("postgresql://", "postgres://")):
        from mcp_firewall.infrastructure.persistence.postgres import PostgresDatabase

        return PostgresDatabase(url)
    if url and url.startswith("sqlite:///"):
        return SqliteDatabase(url.removeprefix("sqlite:///"))
    return SqliteDatabase(settings.sqlite_path)


def make_bus(settings: Settings) -> EventBus:
    if settings.redis_url:
        from mcp_firewall.infrastructure.persistence.redis import RedisEventBus

        return RedisEventBus(settings.redis_url)  # type: ignore[return-value]
    return InMemoryEventBus()  # type: ignore[return-value]


@dataclass
class Container:
    settings: Settings
    db: Database
    repo: SqlRepository
    audit_log: SqlAuditLog
    audit: AuditService
    bus: EventBus
    policy_engine: PolicyEngine
    approvals: ApprovalService
    executor: ExecutionService
    interception: InterceptionService
    upstream: UpstreamManager | None
    sanitizer: Sanitizer
    metrics: PrometheusMetrics
    approver_auth: TokenAuthenticator
    client_auth: TokenAuthenticator
    approve: ApproveRequest
    reject: RejectRequest
    owner_id: str
    policies_file: Path | None = None
    _sweeper: asyncio.Task[None] | None = field(default=None, repr=False)

    async def start(self) -> None:
        await self.db.start()
        await ensure_schema(self.db)
        await self.bus.start()
        await self.approvals.start()
        for principal in self.approver_auth.principals():
            await self.repo.upsert_principal(principal)
        await self.repo.save_policy_snapshot(self.policy_engine.policy, self.settings.tenant_id)
        if self.upstream is not None:
            config = getattr(self.upstream, "config", None)
            for cfg in config.servers if config is not None else []:
                endpoint = cfg.command or cfg.url or ""
                await self.repo.upsert_server(
                    name=cfg.name,
                    transport=cfg.transport,
                    endpoint_ref=endpoint.split("?")[0],
                    enabled=cfg.enabled,
                )
            await self.upstream.start()
        await self.interception.sweep(self.settings.execution_timeout_seconds + 30)  # recover abandoned work
        self._sweeper = asyncio.create_task(self._sweep_loop(), name="request-reaper")
        await self.audit.record(
            AuditEventType.GATEWAY_STARTED,
            None,
            owner=self.owner_id,
            policy_version=self.policy_engine.policy.version,
        )

    async def stop(self) -> None:
        if self._sweeper:
            self._sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._sweeper
        with contextlib.suppress(Exception):
            await self.audit.record(AuditEventType.GATEWAY_STOPPED, None, owner=self.owner_id)
        await self.approvals.stop()
        if self.upstream is not None:
            await self.upstream.stop()
        await self.bus.stop()
        await self.db.stop()

    async def _sweep_loop(self) -> None:
        grace = self.settings.execution_timeout_seconds + 30
        while True:
            await asyncio.sleep(self.settings.sweep_interval_seconds)
            try:
                await self.interception.sweep(grace)
            except Exception:
                log.exception("sweep_failed")

    async def reload_policy(self, actor: str = "system") -> str:
        if self.policies_file is None:
            raise RuntimeError("no policy file configured")
        policy = load_policy_file(self.policies_file)  # raises on invalid file; old policy stays active
        self.policy_engine.replace(policy)
        await self.repo.save_policy_snapshot(policy, self.settings.tenant_id)
        await self.audit.record(AuditEventType.POLICY_RELOADED, None, actor=actor, version=policy.version)
        return policy.version

    async def set_kill_switch(self, enabled: bool, actor: str) -> None:
        await self.repo.set_setting(KILL_SWITCH_KEY, "1" if enabled else "0")
        await self.audit.record(AuditEventType.KILL_SWITCH, None, actor=actor, enabled=enabled)


def build_container(
    settings: Settings,
    *,
    policy: PolicySet,
    upstream: UpstreamManager | None = None,
    notifier: ApproverNotifier | None = None,
    policies_file: Path | None = None,
    db: Database | None = None,
    bus: EventBus | None = None,
    box: SecretBox | None = None,
) -> Container:
    box = box or load_secret_box(settings.home, settings.encryption_key)
    db = db or make_database(settings)
    bus = bus or make_bus(settings)
    sanitizer = Sanitizer()
    metrics = PrometheusMetrics()
    repo = SqlRepository(db, box)
    audit_log = SqlAuditLog(db)
    audit = AuditService(audit_log, sanitizer)
    engine = PolicyEngine(policy)
    owner_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:8]}"

    approvals = ApprovalService(repo, audit, bus, metrics=metrics)

    async def kill_switch() -> bool:
        return (await repo.get_setting(KILL_SWITCH_KEY)) == "1"

    executor = ExecutionService(
        repo,
        upstream if upstream is not None else _NoUpstream(),
        audit,
        execution_timeout=settings.execution_timeout_seconds,
        max_concurrent_per_server=settings.max_concurrent_per_server,
        kill_switch_check=kill_switch,
    )
    interception = InterceptionService(
        repo=repo,
        settings=repo,
        tools=repo,
        audit=audit,
        policy=engine,
        approvals=approvals,
        executor=executor,
        sanitizer=sanitizer,
        bus=bus,
        config=InterceptionConfig(
            approval_timeout=settings.approval_timeout_seconds,
            max_pending=settings.max_pending_requests,
            max_argument_bytes=settings.max_argument_bytes,
            owner_id=owner_id,
        ),
        notifier=notifier or NullNotifier(),
        metrics=metrics,
    )
    return Container(
        settings=settings,
        db=db,
        repo=repo,
        audit_log=audit_log,
        audit=audit,
        bus=bus,
        policy_engine=engine,
        approvals=approvals,
        executor=executor,
        interception=interception,
        upstream=upstream,
        sanitizer=sanitizer,
        metrics=metrics,
        approver_auth=TokenAuthenticator(parse_approver_tokens(settings.approver_tokens)),
        client_auth=TokenAuthenticator(parse_client_tokens(settings.mcp_client_tokens)),
        approve=ApproveRequest(approvals),
        reject=RejectRequest(approvals),
        owner_id=owner_id,
        policies_file=policies_file,
    )


class _NoUpstream:
    """Placeholder used by tests / API-only runs: nothing can be executed."""

    def server_names(self) -> list[str]:
        return []

    async def list_tools(self):
        return []

    async def execute(self, request):
        from mcp_firewall.domain.exceptions import UpstreamUnavailableError

        raise UpstreamUnavailableError("no upstream configured")
