# ── Stage 1: Build dependencies ────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/
# --no-deps intentionally omitted: all transitive deps must resolve at runtime in distroless
RUN pip install --no-cache-dir --prefix=/install -r /tmp/requirements.txt

# Create passwd/group for non-root user (distroless has no useradd)
RUN echo 'cybernova:x:1000:1000:cybernova:/nonexistent:/sbin/nologin' > /tmp/passwd \
    && echo 'cybernova:x:1000:' > /tmp/group

# ── Stage 2: Distroless runtime ───────────────────────────────
FROM gcr.io/distroless/python3-debian12

WORKDIR /app

# Copy pre-built packages from builder stage
COPY --from=builder /install /usr/local
# Copy user config (distroless doesn't have useradd)
COPY --from=builder /tmp/passwd /etc/passwd
COPY --from=builder /tmp/group /etc/group

# Application code
COPY cybernova /app/cybernova
COPY docs /app/docs

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER cybernova

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["/usr/bin/python3", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health',timeout=5).status==200 else 1)"]

CMD ["/usr/bin/python3", "-m", "uvicorn", "cybernova.main:app", "--host", "0.0.0.0", "--port", "8000"]
