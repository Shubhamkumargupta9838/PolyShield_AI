# PolyShield AI — Resume & Portfolio Descriptions

## 1. One-Line Summary
> Built **PolyShield AI**, an AI-powered polymorphic malware detection & analysis platform featuring static PE analysis, PyTorch LSTM sequence modeling, SHAP/Captum explainability, and containerized security microservices.

---

## 2. Two-Bullet Resume Version
- **Multimodal ML Malware Detection Platform**: Engineered a dual-modality malware analysis architecture combining static PE structural analysis (Random Forest/XGBoost on 17 features) and dynamic behavioral sequence modeling (PyTorch LSTM on 256-event sequences) with equal-weight ensemble probability fusion.
- **Production Packaging & Security Hardening**: Implemented JWT RBAC authentication, zero host sample execution controls, safe-root path traversal prevention, non-root Docker containers (`cap_drop: ALL`), and 191 automated test suites in Python and React.

---

## 3. Three-Bullet Resume Version
- **AI-Powered Malware Analysis Pipeline**: Designed and developed an end-to-end security analysis platform integrating FastAPI, Celery, Redis, and MongoDB for asynchronous static PE analysis and dynamic behavioral telemetry processing.
- **Explainable AI Integration**: Integrated SHAP TreeExplainer and Captum LayerIntegratedGradients to provide security analysts with feature-level risk attribution and sequence-step event attributions.
- **Hardened Container Infrastructure**: Implemented multi-stage Docker builds, Nginx strict security headers & CSP, rate limiting, and zero host subprocess sample execution boundaries.
