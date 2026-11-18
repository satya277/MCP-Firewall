"""Domain and application exceptions. None of these carry secrets in their messages."""

from __future__ import annotations


class FirewallError(Exception):
    """Base class for all expected firewall errors."""


class InvalidRequestError(FirewallError):
    """The incoming MCP message is malformed, oversized or fails schema validation."""


class InvalidTransitionError(FirewallError):
    """A request lifecycle transition was attempted that the state machine forbids."""


class ConcurrentModificationError(FirewallError):
    """An atomic conditional update lost the race (someone else already moved the request)."""


class KillSwitchActive(FirewallError):
    """The emergency kill switch is engaged; no tool execution is permitted."""


class TooManyPendingError(FirewallError):
    """The bounded pending-approval queue is full."""


class ApprovalChannelUnavailable(FirewallError):
    """No approver can currently be reached; approval-required requests must fail closed."""


class ApprovalError(FirewallError):
    """Base class for errors when submitting a decision."""

    code = "approval_error"


class UnknownRequestError(ApprovalError):
    code = "unknown_request"


class AlreadyDecidedError(ApprovalError):
    code = "already_decided"


class ApprovalExpiredError(ApprovalError):
    code = "expired"


class HashMismatchError(ApprovalError):
    code = "hash_mismatch"


class NotAuthorizedError(ApprovalError):
    code = "not_authorized"


class StrongConfirmationRequired(ApprovalError):
    code = "strong_confirmation_required"


class IntegrityError(FirewallError):
    """The frozen request no longer matches the hash that was approved (tampering / TOCTOU)."""


class UpstreamUnavailableError(FirewallError):
    """The upstream MCP server is not connected. The call was NOT sent."""


class UpstreamTimeoutError(FirewallError):
    """The upstream call was sent but did not answer in time. The outcome is unknown."""


class UpstreamCommunicationError(FirewallError):
    """The connection broke after the call was sent. The outcome is unknown."""
