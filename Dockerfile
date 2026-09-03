# =============================================================================
# Multi-stage Dockerfile for SentinelGPT FastAPI Backend
# =============================================================================

FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install the locked, hash-pinned dependency set (SRS Chapter 3, Section 18).
# The lock is regenerated inside linux/python:3.12 — see requirements.lock header.
COPY requirements.lock ./
RUN pip install --upgrade pip \
    && pip install --target=/deps --require-hashes -r requirements.lock

# -----------------------------------------------------------------------------
# Runtime Stage
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # ``src`` package root's PARENT must be importable (backend/ -> src/)
    PYTHONPATH=/app/backend:/app

# Install runtime dependencies (e.g., curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for least privilege security
RUN useradd -m -u 1000 appuser

COPY --from=builder /deps /usr/local/lib/python3.12/site-packages
COPY backend/src /app/backend/src
COPY alembic.ini /app/alembic.ini

USER appuser

# Cloud Run injects PORT (default 8080 there); compose and local runs keep
# the historical 8000 default so healthchecks and overrides stay valid.
ENV PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f "http://localhost:${PORT}/healthz" || exit 1

# Console scripts of --target installs are not on PATH; invoke uvicorn as a
# module so the locked dependency set is used exactly as installed. The
# shell form lets ${PORT} expand at run time.
CMD ["sh", "-c", "python -m uvicorn src.main:app --host 0.0.0.0 --port \"${PORT:-8000}\""]
