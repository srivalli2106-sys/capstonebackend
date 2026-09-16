# syntax=docker/dockerfile:1

# Production image for the Secure Messaging backend.
#
# Design notes:
#   * slim base + pinned, hashed-dependency install -> small, reproducible image.
#   * Runtime only: tests, lint and dev tooling are never copied or installed.
#   * Non-root runtime user (least privilege).
#   * No secrets are baked in; all credentials arrive via environment at run time.
#     APP_ENV=production makes startup fail fast if those settings are missing/unsafe.
#   * A single server process is expected: the WebSocket registry, presence and
#     rate limiting are process-local by design. Do NOT scale workers without
#     first making that shared state external (see docs/DEPLOYMENT.md).

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install pinned runtime dependencies first for Docker layer caching.
# --require-hashes is deliberately NOT used here (hash pinning is managed in
# requirements.txt); if you want hermetic builds, generate constrained hashes
# with `pip-tools` and re-run `pip install --require-hashes`.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code only (see .dockerignore).
COPY server ./server

# Non-root runtime user. 10001 is an unprivileged UID (no login shell, no HOME).
RUN useradd --create-home --shell /usr/sbin/nologin --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Liveness probe without extra tools in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"]

# Run the production ASGI server. Single worker (see design note above).
# --proxy-headers: honour X-Forwarded-* so client IPs used for rate limiting
# are correct behind a reverse proxy. By default only requests arriving from
# 127.0.0.1 are trusted; override --forwarded-allow-ips with the trusted proxy
# address/CIDR when deploying (see docs/DEPLOYMENT.md).
CMD ["python", "-m", "uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--proxy-headers"]