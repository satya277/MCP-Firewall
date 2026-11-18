"""Redaction of secrets for logs, audit metadata and the approval UI.

Redaction is applied to *copies* used for display; the hash and the dispatched payload always
use the original arguments.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|credential|"
    r"session[_-]?id|bearer|client[_-]?secret|access[_-]?key)",
    re.IGNORECASE,
)
_SECRET_VALUES = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),  # OpenAI-style
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),  # GitHub
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),  # JWT
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-~+/=]{16,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*)[^\s'\",;&]+"),
]


class Sanitizer:
    def __init__(self, max_string: int = 4000, max_depth: int = 20) -> None:
        self._max_string = max_string
        self._max_depth = max_depth

    def redact_text(self, text: str) -> str:
        for pattern in _SECRET_VALUES:
            if pattern.groups:
                text = pattern.sub(lambda m: m.group(1) + REDACTED, text)
            else:
                text = pattern.sub(REDACTED, text)
        return text

    def sanitize(self, value: Any, _depth: int = 0) -> Any:
        if _depth > self._max_depth:
            return "[too deep]"
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                if isinstance(key, str) and _SENSITIVE_KEY.search(key) and not isinstance(item, (dict, list)):
                    out[key] = REDACTED
                else:
                    out[str(key)] = self.sanitize(item, _depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [self.sanitize(item, _depth + 1) for item in value]
        if isinstance(value, str):
            text = self.redact_text(value)
            if len(text) > self._max_string:
                return f"{text[: self._max_string]}…[truncated, {len(value)} chars total]"
            return text
        return value
