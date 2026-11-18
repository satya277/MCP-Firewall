"""Minimal async database port shared by the SQLite and PostgreSQL adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

Row = dict[str, Any]


class Executor(Protocol):
    async def execute(self, sql: str, params: tuple = ()) -> int: ...

    async def fetchone(self, sql: str, params: tuple = ()) -> Row | None: ...

    async def fetchall(self, sql: str, params: tuple = ()) -> list[Row]: ...


class Database(Executor, Protocol):
    dialect: str

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    def transaction(self, exclusive: bool = False) -> AbstractAsyncContextManager[Executor]:
        """All statements inside commit atomically. ``exclusive`` serializes writers (audit chain)."""
        ...

    async def ping(self) -> bool: ...


__all__ = ["Database", "Executor", "Row", "AsyncIterator"]
