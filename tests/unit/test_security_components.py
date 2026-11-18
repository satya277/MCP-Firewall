"""Unit tests: sanitizer, authentication, rate limiter, SSRF validation, secrets."""

from __future__ import annotations

import socket

import pytest
from cryptography.fernet import Fernet

from mcp_firewall.domain.enums.decision import Role
from mcp_firewall.infrastructure.security.authentication import (
    TokenAuthenticator,
    generate_token,
    hash_token,
    parse_approver_tokens,
    parse_client_tokens,
)
from mcp_firewall.infrastructure.security.authorization import RateLimiter
from mcp_firewall.infrastructure.security.sanitizer import REDACTED, Sanitizer
from mcp_firewall.infrastructure.security.secrets_manager import SecretBox, load_secret_box, resolve_refs
from mcp_firewall.infrastructure.security.ssrf import UnsafeUpstreamError, validate_remote_url

S = Sanitizer()


def test_redacts_sensitive_keys_recursively():
    out = S.sanitize(
        {"password": "hunter2", "nested": {"api_key": "abc", "ok": "visible"}, "list": [{"token": "t"}]}
    )
    assert out["password"] == REDACTED
    assert out["nested"]["api_key"] == REDACTED and out["nested"]["ok"] == "visible"
    assert out["list"][0]["token"] == REDACTED


@pytest.mark.parametrize(
    "secret",
    [
        "sk-abcdefghijklmnopqrstuvwxyz123456",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "xoxb-1234567890-abcdefghij",
    ],
)
def test_redacts_secret_shaped_values_in_text(secret):
    out = S.sanitize({"note": f"use {secret} for auth"})
    assert secret not in out["note"] and REDACTED in out["note"]


def test_redacts_inline_assignments_and_private_keys():
    assert "hunter2" not in S.redact_text("connect with password=hunter2 now")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIabc" not in S.redact_text(pem)


def test_truncates_long_strings_and_deep_structures():
    out = S.sanitize({"v": "x" * 10_000})
    assert "truncated" in out["v"] and len(out["v"]) < 4200
    deep: dict = {}
    cur = deep
    for _ in range(40):
        cur["n"] = {}
        cur = cur["n"]
    assert "too deep" in str(S.sanitize(deep))


def test_sanitize_does_not_mutate_input():
    data = {"password": "p"}
    S.sanitize(data)
    assert data["password"] == "p"


def test_token_authenticator_roundtrip_and_rejections():
    auth = TokenAuthenticator()
    token = generate_token()
    from mcp_firewall.domain.entities.approval import Principal

    auth.add(Principal("alice", Role.APPROVER), token)
    assert auth.authenticate(token).id == "alice"
    for bad in (None, "", "x", token + "x", token.upper(), "a" * 600):
        assert auth.authenticate(bad) is None


def test_token_hash_parsing():
    token = generate_token()
    entries = parse_approver_tokens(f"alice:admin:{hash_token(token)}:acme, bob:viewer:{hash_token('t2')}")
    assert entries[0].principal.role is Role.ADMIN and entries[0].principal.tenant_id == "acme"
    assert entries[1].principal.tenant_id == "default"
    assert parse_client_tokens(f"web:{hash_token('x')}")[0].principal.id == "web"
    for bad in ("alice:admin:short", "alice:root:" + "a" * 64, "alice", "x:admin:" + "g" * 64):
        with pytest.raises(ValueError):
            parse_approver_tokens(bad)


def test_rate_limiter_bursts_and_refills(monkeypatch):
    import mcp_firewall.infrastructure.security.authorization as mod

    now = [100.0]
    monkeypatch.setattr(mod.time, "monotonic", lambda: now[0])
    limiter = RateLimiter(rate_per_second=1, burst=3)
    assert [limiter.allow("k") for _ in range(4)] == [True, True, True, False]
    assert limiter.blocked("k")
    now[0] += 2
    assert limiter.allow("k") and not limiter.blocked("other")


def test_rate_limiter_bounded_keys():
    limiter = RateLimiter(1, 1, max_keys=5)
    for i in range(50):
        limiter.allow(str(i))
    assert len(limiter._buckets) <= 5


def _fake_resolver(monkeypatch, ip):
    def fake(host, port, type=0):  # noqa: A002
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "172.16.0.1", "0.0.0.0"]
)
def test_ssrf_blocks_private_addresses(monkeypatch, ip):
    _fake_resolver(monkeypatch, ip)
    with pytest.raises(UnsafeUpstreamError):
        validate_remote_url("https://evil.example.com/mcp")


def test_ssrf_allows_public_and_explicit_hosts(monkeypatch):
    _fake_resolver(monkeypatch, "93.184.216.34")
    validate_remote_url("https://example.com/mcp")
    _fake_resolver(monkeypatch, "10.1.2.3")
    validate_remote_url("https://internal.corp/mcp", allowed_hosts=frozenset({"internal.corp"}))


def test_ssrf_scheme_and_credentials(monkeypatch):
    _fake_resolver(monkeypatch, "93.184.216.34")
    for url in (
        "http://example.com/mcp",
        "ftp://example.com/x",
        "https://user:pw@example.com/mcp",
        "https:///x",
    ):
        with pytest.raises(UnsafeUpstreamError):
            validate_remote_url(url)
    _fake_resolver(monkeypatch, "127.0.0.1")
    validate_remote_url("http://localhost:9000/mcp", allow_insecure_loopback=True)
    with pytest.raises(UnsafeUpstreamError):
        validate_remote_url("http://localhost:9000/mcp")


def test_ssrf_unresolvable_host(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(UnsafeUpstreamError):
        validate_remote_url("https://nonexistent.invalid/mcp")


def test_secretbox_roundtrip_and_wrong_key():
    box = SecretBox(Fernet.generate_key())
    token = box.encrypt('{"a":"secret"}')
    assert "secret" not in token and box.decrypt(token) == '{"a":"secret"}'
    with pytest.raises(ValueError):
        SecretBox(Fernet.generate_key()).decrypt(token)


def test_key_file_created_once_and_reused(tmp_path):
    a = load_secret_box(tmp_path, use_keyring=False)
    b = load_secret_box(tmp_path, use_keyring=False)
    assert b.decrypt(a.encrypt("hello")) == "hello"
    assert (tmp_path / "secret.key").exists()


def test_resolve_refs():
    assert resolve_refs("Bearer ${T}", {"T": "abc"}) == "Bearer abc"
    with pytest.raises(ValueError):
        resolve_refs("${MISSING_VAR}", {})
