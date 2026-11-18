"""SSRF defenses for remote (Streamable HTTP) upstream URLs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

from mcp_firewall.domain.exceptions import FirewallError


class UnsafeUpstreamError(FirewallError):
    """The configured upstream URL fails SSRF validation."""


def _is_forbidden(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_remote_url(
    url: str,
    *,
    allowed_hosts: frozenset[str] = frozenset(),
    allow_insecure_loopback: bool = False,
) -> None:
    """Raise UnsafeUpstreamError unless ``url`` is an https URL to a public (or explicitly allowed) host."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        raise UnsafeUpstreamError("upstream URL has no host")
    if parts.username or parts.password:
        raise UnsafeUpstreamError("credentials in the upstream URL are not allowed; use headers")
    explicitly_allowed = host in allowed_hosts

    try:
        infos = socket.getaddrinfo(
            host, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise UnsafeUpstreamError(f"cannot resolve upstream host {host!r}") from exc
    addresses = {ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos}
    loopback_only = bool(addresses) and all(a.is_loopback for a in addresses)

    if parts.scheme == "http":
        if not (allow_insecure_loopback and loopback_only):
            raise UnsafeUpstreamError("plain http is only allowed for loopback when explicitly enabled")
    elif parts.scheme != "https":
        raise UnsafeUpstreamError(f"unsupported upstream scheme {parts.scheme!r}")

    if not explicitly_allowed and not (allow_insecure_loopback and loopback_only):
        bad = [str(a) for a in addresses if _is_forbidden(a)]
        if bad:
            raise UnsafeUpstreamError(
                f"upstream host {host!r} resolves to a non-public address; add it to allowed_hosts to permit"
            )


async def validate_remote_url_async(url: str, **kwargs) -> None:
    await asyncio.to_thread(validate_remote_url, url, **kwargs)
