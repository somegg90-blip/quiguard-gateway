# =============================================================
# QuiGuard Backend — Production Dockerfile (Render Free Tier)
# Optimized for 512MB RAM
# =============================================================

FROM python:3.11-slim

WORKDIR /app

# ---- System Dependencies ----
# python3-dev needed for some pip packages to build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# ---- Python Dependencies ----
# Copy requirements first (layer caching — only rebuilds when requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ---- Download SpaCy Model ----
RUN python -m spacy download en_core_web_sm
RUN python -m spacy download en_core_web_lg

# ---- Application Code ----
COPY app ./app
COPY policy.yaml .

# ---- Expose Port ----
EXPOSE 8000

# ---- Health Check ----
# Render pings this to detect if the service is alive
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# ---- Start Command ----
# gunicorn for production (multiple workers, graceful restarts)
CMD gunicorn app.main:app --bind 0.0.0.0:${PORT:-8000} --workers 1 --worker-class uvicorn.workers.UvicornWorker --timeout 120 --graceful-timeout 30 --access-logfile -