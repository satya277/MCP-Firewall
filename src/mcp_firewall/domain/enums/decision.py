"""Decision, policy-action, risk and role enumerations."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Decision(StrEnum):
    """A human approver's verdict on one pending request."""

    ALLOW = "allow"
    BLOCK = "block"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class RiskLevel(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name


class Role(IntEnum):
    VIEWER = 1
    APPROVER = 2
    ADMIN = 3

    @classmethod
    def parse(cls, value: str) -> Role:
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown role: {value!r}") from exc
