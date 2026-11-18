FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --create-home --uid 10001 mcpfw
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install ".[postgres,redis]"
COPY config ./config
COPY demo ./demo

USER mcpfw
ENV MCPFW_HOME=/home/mcpfw/.mcp-firewall
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"
# Behind a TLS-terminating reverse proxy; --forwarded-allow-ips must list that proxy.
CMD ["python", "-m", "mcp_firewall", "serve", "--host", "0.0.0.0", "--port", "8080"]
