# PolyShield AI — Production Deployment Guide

## 1. Architecture Overview

PolyShield AI production architecture employs a containerized multi-tier microservices design with network segmentation:

```text
                                Internet
                                   |
                             [Reverse Proxy / TLS]
                                   |
                       +-----------+-----------+
                       |                       |
               [React Production UI]    [FastAPI Backend]
                 (Nginx Container)      (Uvicorn / 4 Workers)
                       |                       |
                       +-----------+-----------+
                                   |
                           +-------+-------+
                           |               |
                      [MongoDB 6.0]   [Redis 7.0]
                                           |
                                    [Celery Worker]
```

### Network Isolation Boundaries
1. **`frontend-edge`**: External Nginx reverse proxy / static asset server receiving HTTP/HTTPS traffic.
2. **`internal-backend`**: Internal bridge connecting Nginx to the FastAPI application server.
3. **`internal-db`**: Strictly private network connecting FastAPI and Celery workers to MongoDB and Redis. Databases are NOT published on external host ports.

### Core Architecture & Configuration Notes
- **Password Hashing**: Standardized on PBKDF2-HMAC-SHA256 with **600,000 iterations** (OWASP 2023+ standard) using standard library `hashlib`, guaranteeing zero native C-extension binary dependencies. Dynamic iteration parsing supports backwards-compatible verification of legacy hashes.
- **Redis Semantics**: MongoDB is the **single authoritative source** for persistent scans, reports, and XAI metadata. Redis acts as a task broker, result backend, and volatile cache. `redis_prod_data` volume is mounted for Celery task queue recovery across container restarts.
- **Uvicorn Worker Allocation**: Configured with **4 workers** matching the 2.0 CPU / 2048 MB RAM limit (`2 * CPUs`). Heavy CPU dynamic sandboxing and ML tasks are delegated to separate Celery workers.
- **Model Source of Truth**: Deterministic model artifacts (`static_baseline_v2.0.joblib`, `dynamic_lstm_v1.0.pt`) packaged inside container images under `ml/artifacts/models`. Loading strictly validated via safe-root path resolution and SHA-256 integrity verification.
- **Runtime Verification Status**: `DOCKER_RUNTIME_VERIFICATION = NOT_PERFORMED` due to host Docker CLI unavailability. Configuration syntax and static container security pass verification.
- **Scientific Disclosure**:
  ```text
  dataset_provenance_status = SYNTHETIC_FIXTURE
  scientifically_benchmark_ready = false
  ```
---

## 2. Prerequisites & Environment Setup

- **Container Engine**: Docker 24.0+ & Docker Compose v2.20+
- **Host Specs (Recommended)**: 4 vCPU, 8GB RAM, 50GB SSD storage.
- **Environment Configuration**: Create `.env` from `.env.example`:
  ```bash
  cp .env.example .env
  ```

### Critical Production Secrets (MUST be configured in `.env`):
- `ENVIRONMENT="production"`
- `DEBUG=false`
- `SECRET_KEY="<insert_random_512bit_hex_secret>"`
- `JWT_SECRET_KEY="<insert_random_256bit_hex_jwt_secret>"`
- `MONGODB_URL="mongodb://mongodb:27017"`
- `REDIS_URL="redis://redis:6379/0"`

---

## 3. Build & Deployment Commands

### Build Production Containers
```bash
docker compose -f docker-compose.prod.yml build
```

### Start Production Stack
```bash
docker compose -f docker-compose.prod.yml up -d
```

### Check Container Status & Health
```bash
docker compose -f docker-compose.prod.yml ps
```

---

## 4. Health Verification & Probes

| Endpoint | Probe Type | Purpose | Success Condition |
| :--- | :--- | :--- | :--- |
| `GET /api/v1/health/liveness` | Liveness | Verifies FastAPI process is responsive | HTTP 200 `{"status": "ALIVE"}` |
| `GET /api/v1/health/readiness` | Readiness | Verifies DB & Cache connectivity | HTTP 200 `{"status": "READY"}` |
| `GET /api/v1/health` | System Health | Full dependency state report | HTTP 200 `{"status": "healthy"}` |

---

## 5. Upgrade & Rollback Strategy

### Rolling Update
1. Pull / rebuild updated image tags.
2. Execute graceful container replacement:
   ```bash
   docker compose -f docker-compose.prod.yml up -d --no-deps --build backend worker
   ```

### Rollback Procedure
1. Re-tag prior stable release commit.
2. Restart services using cached image tag:
   ```bash
   docker compose -f docker-compose.prod.yml up -d
   ```

---

## 6. Shutdown Procedure

```bash
docker compose -f docker-compose.prod.yml stop
```
