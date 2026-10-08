FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --default-timeout=1000 --no-cache-dir -r backend/requirements.txt

# Copy application source code
COPY backend /app/backend
COPY analysis /app/analysis
COPY ml /app/ml
COPY sandbox /app/sandbox

# Create non-root user and assign permissions
RUN useradd -m -u 10001 polyshield && \
    mkdir -p /app/data/storage /app/data/logs && \
    chown -R polyshield:polyshield /app

USER polyshield

ENV PYTHONPATH=/app:/app/backend
ENV ENVIRONMENT=development
ENV DEBUG=false

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health/liveness || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
