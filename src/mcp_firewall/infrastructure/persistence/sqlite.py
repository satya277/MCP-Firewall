"""SQLite adapter (default for the local desktop gateway). WAL mode, safe across processes."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from mcp_firewall.infrastructure.persistence.database import Row


class _Tx:
    def __init__(self, conn: aiosqlite.Connection) -> None:
        self._conn = conn

    async def execute(self, sql: str, params: tuple = ()) -> int:
        cur = await self._conn.execute(sql, params)
        count = cur.rowcount
        await cur.close()
        return count

    async def fetchone(self, sql: str, params: tuple = ()) -> Row | None:
        cur = await self._conn.execute(sql, params)
        row = await cur.fetchone()
        await cur.close()
        return dict(row) if row else None

    async def fetchall(self, sql: str, params: tuple = ()) -> list[Row]:
        cur = await self._conn.execute(sql, params)
        rows = await cur.fetchall()
        await cur.close()
        return [dict(r) for r in rows]


class SqliteDatabase:
    dialect = "sqlite"

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()
        self._tx: _Tx | None = None

    async def start(self) -> None:
        if self._path != ":memory:":
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(self._path, isolation_level=None)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA synchronous=FULL")
        await conn.execute("PRAGMA busy_timeout=15000")
        await conn.execute("PRAGMA foreign_keys=ON")
        self._conn = conn
        self._tx = _Tx(conn)

    async def stop(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    def _require(self) -> _Tx:
        if self._tx is None:
            raise RuntimeError("database is not started")
        return self._tx

    async def execute(self, sql: str, params: tuple = ()) -> int:
        async with self._lock:
            return await self._require().execute(sql, params)

    async def fetchone(self, sql: str, params: tuple = ()) -> Row | None:
        async with self._lock:
            return await self._require().fetchone(sql, params)

    async def fetchall(self, sql: str, params: tuple = ()) -> list[Row]:
        async with self._lock:
            return await self._require().fetchall(sql, params)

    @asynccontextmanager
    async def transaction(self, exclusive: bool = False) -> AsyncIterator[_Tx]:
        tx = self._require()
        async with self._lock:
            await tx.execute("BEGIN IMMEDIATE")  # takes the write lock up front (cross-process safe)
            try:
                yield tx
            except BaseException:
                await tx.execute("ROLLBACK")
                raise
            else:
                await tx.execute("COMMIT")

    async def ping(self) -> bool:
        try:
            await self.fetchone("SELECT 1 AS ok")
            return True
        except Exception:
            return False
