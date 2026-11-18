"""Use case: a client asked to run a tool / read a resource."""

from __future__ import annotations

from mcp_firewall.application.services.interception_service import (
    IncomingCall,
    InterceptionOutcome,
    InterceptionService,
)


class InterceptRequest:
    def __init__(self, interception: InterceptionService) -> None:
        self._interception = interception

    async def __call__(self, call: IncomingCall) -> InterceptionOutcome:
        return await self._interception.intercept(call)
