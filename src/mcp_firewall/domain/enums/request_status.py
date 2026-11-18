"""Request lifecycle states and the legal transitions between them."""

from __future__ import annotations

from enum import StrEnum


class RequestStatus(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    DENIED = "DENIED"  # refused by policy / validation / kill switch; never shown to a human
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"  # client went away or cancelled while the request was pending
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"  # upstream was known not to have run the call
    EXECUTION_UNKNOWN = "EXECUTION_UNKNOWN"  # call may have executed but the outcome was lost

    @property
    def is_terminal(self) -> bool:
        return self in TERMINAL_STATES


S = RequestStatus

ALLOWED_TRANSITIONS: dict[RequestStatus, frozenset[RequestStatus]] = {
    S.RECEIVED: frozenset({S.VALIDATED, S.DENIED, S.CANCELLED}),
    S.VALIDATED: frozenset({S.PENDING_APPROVAL, S.APPROVED, S.DENIED, S.CANCELLED}),
    S.PENDING_APPROVAL: frozenset({S.APPROVED, S.REJECTED, S.EXPIRED, S.CANCELLED}),
    S.APPROVED: frozenset({S.EXECUTING, S.EXPIRED, S.CANCELLED, S.FAILED}),
    S.EXECUTING: frozenset({S.COMPLETED, S.FAILED, S.EXECUTION_UNKNOWN}),
    S.REJECTED: frozenset(),
    S.DENIED: frozenset(),
    S.EXPIRED: frozenset(),
    S.CANCELLED: frozenset(),
    S.COMPLETED: frozenset(),
    S.FAILED: frozenset(),
    S.EXECUTION_UNKNOWN: frozenset(),
}

TERMINAL_STATES: frozenset[RequestStatus] = frozenset(s for s, nxt in ALLOWED_TRANSITIONS.items() if not nxt)

# States a request can be stuck in if its owning worker disappears.
OPEN_STATES: frozenset[RequestStatus] = frozenset({S.RECEIVED, S.VALIDATED, S.PENDING_APPROVAL, S.APPROVED})


def can_transition(current: RequestStatus, target: RequestStatus) -> bool:
    return target in ALLOWED_TRANSITIONS[current]
