"""Optional OpenTelemetry tracing. A no-op unless the ``otel`` extra is installed and configured."""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from typing import Any

_tracer: Any = None


def configure_tracing(service_name: str = "mcp-firewall") -> bool:
    """Enable tracing when OTEL_EXPORTER_OTLP_ENDPOINT is set and the SDK is available."""
    global _tracer
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer(service_name)
        return True
    except ImportError:
        return False


@contextlib.contextmanager
def span(name: str, **attributes: Any) -> Iterator[None]:
    if _tracer is None:
        yield
        return
    with _tracer.start_as_current_span(name) as s:
        for key, value in attributes.items():
            s.set_attribute(key, str(value))
        yield
