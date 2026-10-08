FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend /app/backend
COPY analysis /app/analysis
COPY ml /app/ml
COPY sandbox /app/sandbox

RUN useradd -m -u 10001 polyshield && \
    mkdir -p /app/data/storage /app/data/logs && \
    chown -R polyshield:polyshield /app

USER polyshield

ENV PYTHONPATH=/app:/app/backend
ENV ENVIRONMENT=production

CMD ["celery", "-A", "backend.app.workers.celery_app", "worker", "--loglevel=INFO", "--concurrency=4"]
