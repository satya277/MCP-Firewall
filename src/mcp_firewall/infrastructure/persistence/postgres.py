"""PostgreSQL adapter (remote gateway). Requires the ``postgres`` extra (asyncpg)."""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from mcp_firewall.infrastructure.persistence.database import Row

_AUDIT_LOCK_KEY = 7_281_001


def _convert(sql: str) -> str:
    """Translate ``?`` placeholders to ``$1..$n``."""
    counter = 0

    def sub(_: re.Match[str]) -> str:
        nonlocal counter
        counter += 1
        return f"${counter}"

    return re.sub(r"\?", sub, sql)


def _count(status: str) -> int:
    try:
        return int(status.rsplit(" ", 1)[-1])
    except ValueError:
        return 0


class _PgExec:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    async def execute(self, sql: str, params: tuple = ()) -> int:
        return _count(await self._conn.execute(_convert(sql), *params))

    async def fetchone(self, sql: str, params: tuple = ()) -> Row | None:
        row = await self._conn.fetchrow(_convert(sql), *params)
        return dict(row) if row else None

    async def fetchall(self, sql: str, params: tuple = ()) -> list[Row]:
        return [dict(r) for r in await self._conn.fetch(_convert(sql), *params)]


class PostgresDatabase:
    dialect = "postgres"

    def __init__(self, dsn: str, min_size: int = 1, max_size: int = 10) -> None:
        self._dsn = dsn
        self._min = min_size
        self._max = max_size
        self._pool: Any = None

    async def start(self) -> None:
        import asyncpg  # imported lazily: optional dependency

        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=self._min, max_size=self._max, command_timeout=30
        )

    async def stop(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def execute(self, sql: str, params: tuple = ()) -> int:
        async with self._pool.acquire() as conn:
            return await _PgExec(conn).execute(sql, params)

    async def fetchone(self, sql: str, params: tuple = ()) -> Row | None:
        async with self._pool.acquire() as conn:
            return await _PgExec(conn).fetchone(sql, params)

    async def fetchall(self, sql: str, params: tuple = ()) -> list[Row]:
        async with self._pool.acquire() as conn:
            return await _PgExec(conn).fetchall(sql, params)

    @asynccontextmanager
    async def transaction(self, exclusive: bool = False) -> AsyncIterator[_PgExec]:
        async with self._pool.acquire() as conn, conn.transaction():
            if exclusive:
                await conn.execute("SELECT pg_advisory_xact_lock($1)", _AUDIT_LOCK_KEY)
            yield _PgExec(conn)

    async def ping(self) -> bool:
        try:
            await self.fetchone("SELECT 1 AS ok")
            return True
        except Exception:
            return False
