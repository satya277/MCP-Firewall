"""Prometheus metrics (implements the application-layer MetricsPort)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest


class PrometheusMetrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self._requests = Counter(
            "mcpfw_requests_total",
            "Intercepted requests by final status",
            ["status", "operation"],
            registry=self.registry,
        )
        self._latency = Histogram(
            "mcpfw_approval_seconds",
            "Time from interception to human decision",
            ["outcome"],
            buckets=(1, 2, 5, 10, 20, 30, 60, 120, 300),
            registry=self.registry,
        )
        self._pending = Gauge(
            "mcpfw_pending_requests", "Requests waiting for approval", registry=self.registry
        )
        self._security = Counter(
            "mcpfw_security_events_total", "Security-relevant events", ["kind"], registry=self.registry
        )

    def request_finished(self, status: str, operation: str) -> None:
        self._requests.labels(status=status, operation=operation).inc()

    def approval_latency(self, seconds: float, outcome: str) -> None:
        self._latency.labels(outcome=outcome).observe(max(0.0, seconds))

    def pending_changed(self, delta: int) -> None:
        self._pending.inc(delta)

    def security_event(self, kind: str) -> None:
        self._security.labels(kind=kind).inc()

    def render(self) -> bytes:
        return generate_latest(self.registry)
