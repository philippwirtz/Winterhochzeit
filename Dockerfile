FROM python:3.11-slim

WORKDIR /app

# Systemabhängigkeiten minimal (bei Bedarf erweitern)
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App-Code
COPY . .

# Gunicorn als Entrypoint
ENV PYTHONUNBUFFERED=1
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers=3", "--threads=2", "--timeout=60", "app:app"]
