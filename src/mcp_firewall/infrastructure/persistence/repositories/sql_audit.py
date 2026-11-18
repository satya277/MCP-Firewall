"""Append-only, hash-chained audit log (tamper-evident)."""

from __future__ import annotations

import dataclasses
import hashlib
import json

from mcp_firewall.domain.entities.audit import AuditEvent
from mcp_firewall.infrastructure.persistence.database import Database, Row

GENESIS = "0" * 64


def compute_event_hash(prev_hash: str, event: AuditEvent) -> str:
    body = json.dumps(
        {
            "id": event.id,
            "seq": event.seq,
            "ts": event.timestamp,
            "tenant": event.tenant_id,
            "request": event.request_id,
            "type": event.event_type,
            "actor": event.actor_id,
            "meta": event.metadata,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256((prev_hash + body).encode("utf-8")).hexdigest()


def _to_event(row: Row) -> AuditEvent:
    return AuditEvent(
        id=row["id"],
        seq=int(row["seq"]),
        timestamp=row["timestamp"],
        tenant_id=row["tenant_id"],
        request_id=row["request_id"],
        event_type=row["event_type"],
        actor_id=row["actor_id"],
        metadata=json.loads(row["metadata"]),
        prev_hash=row["prev_hash"],
        hash=row["hash"],
    )


class SqlAuditLog:
    def __init__(self, db: Database) -> None:
        self._db = db

    async def append(self, event: AuditEvent) -> AuditEvent:
        # Round-trip through JSON so the hashed form equals the stored/verified form.
        meta = json.loads(json.dumps(event.metadata, default=str))
        async with self._db.transaction(exclusive=True) as tx:
            last = await tx.fetchone("SELECT seq, hash FROM audit_logs ORDER BY seq DESC LIMIT 1")
            seq = (int(last["seq"]) + 1) if last else 1
            prev = last["hash"] if last else GENESIS
            sealed = dataclasses.replace(event, seq=seq, prev_hash=prev, metadata=meta)
            sealed = dataclasses.replace(sealed, hash=compute_event_hash(prev, sealed))
            await tx.execute(
                "INSERT INTO audit_logs (seq, id, tenant_id, request_id, event_type, actor_id, timestamp, "
                "metadata, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    sealed.seq, sealed.id, sealed.tenant_id, sealed.request_id, sealed.event_type,
                    sealed.actor_id, sealed.timestamp, json.dumps(meta, sort_keys=True), prev, sealed.hash,
                ),
            )  # fmt: skip
        return sealed

    async def list_events(
        self, *, request_id: str | None = None, limit: int = 200, after_seq: int = 0
    ) -> list[AuditEvent]:
        limit = max(1, min(limit, 1000))
        if request_id:
            rows = await self._db.fetchall(
                "SELECT * FROM audit_logs WHERE request_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?",
                (request_id, after_seq, limit),
            )
        else:
            rows = await self._db.fetchall(
                "SELECT * FROM audit_logs WHERE seq > ? ORDER BY seq ASC LIMIT ?", (after_seq, limit)
            )
        return [_to_event(r) for r in rows]

    async def verify_chain(self) -> tuple[bool, int, str | None]:
        prev, expected_seq, checked, after = GENESIS, 1, 0, 0
        while True:
            rows = await self._db.fetchall(
                "SELECT * FROM audit_logs WHERE seq > ? ORDER BY seq ASC LIMIT 500", (after,)
            )
            if not rows:
                return True, checked, None
            for row in rows:
                event = _to_event(row)
                if event.seq != expected_seq:
                    return False, checked, f"gap or reorder at seq {event.seq} (expected {expected_seq})"
                if event.prev_hash != prev or compute_event_hash(prev, event) != event.hash:
                    return False, checked, f"hash mismatch at seq {event.seq}"
                prev, expected_seq, checked, after = event.hash, expected_seq + 1, checked + 1, event.seq
