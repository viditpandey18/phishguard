# syntax=docker/dockerfile:1.7
# Python 3.12 in the image: mature wheels for numpy/torch/sklearn. Code supports 3.11+.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first for layer caching.
COPY pyproject.toml README.md ./
COPY phishguard ./phishguard
ARG EXTRAS=""
RUN pip install --upgrade pip && pip install ".${EXTRAS:+[$EXTRAS]}"

# Unprivileged runtime user; app files are read-only to it.
RUN useradd --system --uid 10001 --no-create-home phishguard \
    && mkdir -p /app/data/feedback \
    && chown -R phishguard /app/data/feedback
USER phishguard

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status==200 else 1)"

# --proxy-headers only matters when PG_TRUST_PROXY_HEADERS=true behind a trusted proxy.
CMD ["uvicorn", "phishguard.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-server-header"]
