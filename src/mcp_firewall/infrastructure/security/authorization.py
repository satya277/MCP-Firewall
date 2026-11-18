"""Authorization helpers and a small token-bucket rate limiter."""

from __future__ import annotations

import time
from collections import OrderedDict

from mcp_firewall.domain.entities.approval import Principal
from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.domain.exceptions import NotAuthorizedError


def require_role(principal: Principal, minimum: Role) -> None:
    if not principal.can(minimum):
        raise NotAuthorizedError(f"requires role {minimum.name.lower()}")


class RateLimiter:
    """Per-key token bucket (in-memory, bounded number of tracked keys)."""

    def __init__(self, rate_per_second: float, burst: int, max_keys: int = 10_000) -> None:
        self._rate = rate_per_second
        self._burst = float(burst)
        self._max_keys = max_keys
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def blocked(self, key: str) -> bool:
        """True if the bucket is exhausted (does not consume a token)."""
        entry = self._buckets.get(key)
        if entry is None:
            return False
        tokens, last = entry
        return min(self._burst, tokens + (time.monotonic() - last) * self._rate) < 1.0

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self._buckets.pop(key, (self._burst, now))
        tokens = min(self._burst, tokens + (now - last) * self._rate)
        allowed = tokens >= 1.0
        if allowed:
            tokens -= 1.0
        self._buckets[key] = (tokens, now)
        while len(self._buckets) > self._max_keys:
            self._buckets.popitem(last=False)
        return allowed
