"""Bearer-token authentication. Only SHA-256 hashes of tokens are ever stored or configured."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role

TOKEN_PREFIX = "mcpfw_"  # noqa: S105


def generate_token() -> str:
    return TOKEN_PREFIX + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TokenEntry:
    principal: Principal
    token_hash: str


class TokenAuthenticator:
    """Authenticates a presented token against configured hashes in constant time."""

    def __init__(self, entries: list[TokenEntry] | None = None) -> None:
        self._entries = list(entries or [])

    @property
    def configured(self) -> bool:
        return bool(self._entries)

    def add(self, principal: Principal, token: str) -> None:
        self._entries.append(TokenEntry(principal, hash_token(token)))

    def authenticate(self, token: str | None) -> Principal | None:
        if not token or len(token) > 512:
            return None
        presented = hash_token(token)
        found: Principal | None = None
        for entry in self._entries:  # no early exit: constant work regardless of match position
            if hmac.compare_digest(presented, entry.token_hash) and found is None:
                found = entry.principal
        return found

    def principals(self) -> list[Principal]:
        return [e.principal for e in self._entries]


def _check_hash(value: str) -> str:
    value = value.strip().lower()
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("token hash must be a 64-character SHA-256 hex digest")
    return value


def parse_approver_tokens(spec: str) -> list[TokenEntry]:
    """``id:role:sha256[:tenant]`` entries, comma separated."""
    entries = []
    for chunk in filter(None, (c.strip() for c in spec.split(","))):
        parts = chunk.split(":")
        if len(parts) not in (3, 4):
            raise ValueError("approver token entries must look like id:role:sha256[:tenant]")
        tenant = parts[3] if len(parts) == 4 else "default"
        principal = Principal(id=parts[0], role=Role.parse(parts[1]), tenant_id=tenant)
        entries.append(TokenEntry(principal, _check_hash(parts[2])))
    return entries


def parse_client_tokens(spec: str) -> list[TokenEntry]:
    """``id:sha256`` entries for MCP clients (e.g. the Claude Web connector)."""
    entries = []
    for chunk in filter(None, (c.strip() for c in spec.split(","))):
        parts = chunk.split(":")
        if len(parts) not in (2, 3):
            raise ValueError("client token entries must look like id:sha256[:tenant]")
        tenant = parts[2] if len(parts) == 3 else "default"
        entries.append(TokenEntry(Principal(parts[0], Role.VIEWER, tenant), _check_hash(parts[1])))
    return entries
