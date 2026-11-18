"""Canonical serialization and hashing of MCP requests.

The hash is computed over the *raw* request (before any redaction) and is the single value the
human approval is bound to. Anything that changes the effective call changes the hash.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from mcp_firewall.domain.exceptions import InvalidRequestError

HASH_VERSION = 1
MAX_DEPTH = 32


def _check(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise InvalidRequestError("arguments are nested too deeply")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidRequestError("non-finite numbers are not allowed")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidRequestError("argument keys must be strings")
            _check(item, depth + 1)
        return
    raise InvalidRequestError(f"unsupported argument type: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 safe, finite numbers only."""
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def compute_request_hash(
    *, operation: str, client_id: str, server: str, tool: str, canonical_arguments: str
) -> str:
    envelope = canonical_json(
        {
            "v": HASH_VERSION,
            "op": operation,
            "client": client_id,
            "server": server,
            "tool": tool,
            "args": json.loads(canonical_arguments),
        }
    )
    return hashlib.sha256(envelope.encode("utf-8")).hexdigest()
