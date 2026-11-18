"""Structured logging. Always writes to **stderr**: on STDIO transports stdout carries MCP messages."""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(level: str = "INFO", json_logs: bool = False) -> None:
    logging.basicConfig(stream=sys.stderr, level=level.upper(), format="%(message)s", force=True)
    for noisy in ("httpx", "httpcore", "mcp", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(max(logging.WARNING, logging.getLevelName(level.upper())))
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer() if json_logs else structlog.dev.ConsoleRenderer(colors=False),
    ]
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=False,
    )
