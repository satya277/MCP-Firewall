"""Encryption of sensitive payloads at rest and resolution of secret references.

Key resolution order: ``MCPFW_ENCRYPTION_KEY`` env var -> OS keyring -> key file in the state
directory (created with owner-only permissions).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import structlog
from cryptography.fernet import Fernet, InvalidToken

log = structlog.get_logger("secrets")
_KEYRING_SERVICE = "mcp-firewall"
_KEYRING_USER = "encryption-key"
_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class SecretBox:
    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("cannot decrypt stored payload (wrong key?)") from exc


class NullSecretBox(SecretBox):
    """Identity 'encryption' - for tests only."""

    def __init__(self) -> None:  # noqa: D107
        pass

    def encrypt(self, plaintext: str) -> str:
        return plaintext

    def decrypt(self, token: str) -> str:
        return token


def _from_keyring() -> bytes | None:
    try:
        import keyring

        value = keyring.get_password(_KEYRING_SERVICE, _KEYRING_USER)
        if value:
            return value.encode()
        new = Fernet.generate_key()
        keyring.set_password(_KEYRING_SERVICE, _KEYRING_USER, new.decode())
        return new
    except Exception:
        return None


def load_secret_box(home: Path, env_key: str | None = None, use_keyring: bool = True) -> SecretBox:
    if env_key:
        return SecretBox(env_key.encode())
    if use_keyring and (key := _from_keyring()):
        return SecretBox(key)
    home.mkdir(parents=True, exist_ok=True)
    key_file = home / "secret.key"
    if key_file.exists():
        return SecretBox(key_file.read_bytes().strip())
    key = Fernet.generate_key()
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    log.warning("encryption_key_file_created", path=str(key_file))
    return SecretBox(key)


def resolve_refs(value: str, env: dict[str, str] | None = None) -> str:
    """Expand ``${NAME}`` from the environment; raises if a referenced secret is missing."""
    source = env if env is not None else os.environ

    def sub(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in source:
            raise ValueError(f"environment variable {name} referenced in configuration is not set")
        return source[name]

    return _REF.sub(sub, value)
