# syntax=docker/dockerfile:1
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System-Tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates tini && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Abhängigkeiten zuerst (build-cache)
COPY requirements.txt /app/requirements.txt
RUN pip install -r requirements.txt

# App-Code
COPY . /app

# Non-root user
RUN useradd -m appuser && mkdir -p /app/instance && chown -R appuser:appuser /app
USER appuser

# Flask CLI & Env
ENV FLASK_APP=app.py \
    ENV=production \
    FORCE_HTTPS=1 \
    GATE_ENABLED=1

EXPOSE 8000

# Healthcheck: App antwortet?
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/ || exit 1

# Entrypoint: DB init (idempotent) -> Gunicorn
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["/bin/sh","-lc","flask --app app.py init-db >/dev/null 2>&1 || true && \
    exec gunicorn -w 3 -k gthread -b 0.0.0.0:8000 app:app --timeout 60 --access-logfile - --error-logfile -"]
