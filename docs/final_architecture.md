# PolyShield AI — Final System Architecture

## 1. High-Level System Architecture

PolyShield AI utilizes a decoupled, asynchronous, containerized microservices architecture:

```text
User / Security Analyst
        │
   [React UI] (Nginx Container)
        │
  [FastAPI Backend] (Uvicorn / 4 Workers)
        │
 ┌──────┴──────┐
 │             │
[MongoDB]   [Redis] (Celery Broker & Cache)
               │
        [Celery Worker]
               │
 ┌─────────────┼─────────────┐
 │             │             │
[Static PE]  [Dynamic]  [ML Ensemble]
  Analyzer   Telemetry   & XAI Engine
```

---

## 2. Subsystem Descriptions

### Frontend Layer
- **Technology**: React 18 + JavaScript + Tailwind CSS + Vite.
- **Role**: Provides security analysts with an interactive dashboard for sample uploading, scan tracking, risk visualization, static PE breakdown, dynamic sequence view, and XAI attribution charts.
- **Packaging**: Containerized via multi-stage Docker build served through Nginx edge proxy with strict CSP and security headers.

### API Layer
- **Technology**: FastAPI + Async Pydantic v2 + SlowAPI rate limiting.
- **Role**: Handles RESTful API requests, JWT authentication, RBAC authorization, upload validation, scan job scheduling, and report queries.
- **Workers**: 4 Uvicorn workers configured with 2.0 CPU / 2048 MB RAM limits.

### Storage & Message Broker
- **MongoDB 6.0**: Authoritative durable database for scan state records, report documents, user profiles, and XAI metadata. Connected via Motor async client.
- **Redis 7.0**: In-memory broker for Celery task queues and result caching. Mounted with `redis_prod_data` volume for queue recovery across container restarts.

### Asynchronous Processing Layer
- **Technology**: Celery + Python 3.12.
- **Role**: Executes CPU-intensive static PE analysis, dynamic telemetry normalization, ML inference, and XAI attribution off the main HTTP API thread.

---

## 3. Trust Domains & Security Boundaries

```text
TRUSTED DOMAIN
├── React UI Application
├── FastAPI Backend Server
├── MongoDB Authoritative Storage
├── Redis Broker & Result Cache
├── Celery Task Workers
└── ML Inference Engine & Artifacts

UNTRUSTED DOMAIN (ISOLATED)
├── Uploaded PE Binary Sample
├── Sandbox Guest Virtual Machine
├── Raw Telemetry Logs
└── Extracted Sample Artifacts
```

### Boundary Security Policy
1. **Zero Host Sample Execution**: Uploaded PE files operate strictly as raw in-memory byte buffers or static file artifacts. No `subprocess`, `Popen`, `os.system`, or shell execution is permitted on host.
2. **Safe-Root Path Resolution**: File system access is restricted to allowed directories via `validate_safe_path`. Path traversal attempts (`../`) raise `PathTraversalException`.
3. **Artifact Isolation**: Extracted artifacts are stored in isolated directories with access controlled via scan ownership authorization checks.
