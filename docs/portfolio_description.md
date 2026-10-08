# PolyShield AI — Portfolio & Case Study Description

## Overview
**PolyShield AI** is an open-source AI-powered polymorphic malware detection and analysis platform. It demonstrates how modern security software engineering, machine learning pipelines, and explainable AI can be combined to analyze untrusted PE software binaries safely and effectively.

---

## Key Highlights
- **Dual-Modality ML Pipeline**: Fuses static structural features (`static-v1` 17 features) and dynamic behavioral event sequences (`dynamic-v1` 256 steps) using a multimodal ensemble.
- **Explainable AI (XAI)**: Visualizes top static risk indicators via SHAP and sequence event attributions via Captum LayerIntegratedGradients.
- **Robust Security Engineering**: Enforces zero host sample execution, safe-root path resolution, JWT auth, RBAC authorization, and non-root Docker containers.
- **Full Test Coverage**: Validated by 191 backend unit/integration tests, Vitest frontend tests, and static security audit scripts.

---

## Technical Stack
- **Frontend**: React 18, Vite, Tailwind CSS, Lucide Icons.
- **Backend**: FastAPI, Pydantic v2, Motor, Celery, Redis, MongoDB 6.0.
- **Machine Learning**: Scikit-Learn (Random Forest), XGBoost, PyTorch (LSTM), SHAP, Captum.
- **DevOps & Packaging**: Docker, Docker Compose, Nginx, Pytest, Vitest.
