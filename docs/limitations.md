# PolyShield AI — Explicit Project Limitations & Disclosures

To maintain absolute scientific and engineering honesty, PolyShield AI explicitly documents all system limitations:

## 1. Dataset & Provenance
- **Synthetic Fixture Status**: Current dataset consists of safe in-memory synthetic PE byte streams (`dataset_provenance_status = SYNTHETIC_FIXTURE`).
- **Benchmark Readiness**: Models are trained for engineering smoke validation and pipeline verification. They are **NOT** scientifically benchmarked against real-world malware corpora (`scientifically_benchmark_ready = false`).

## 2. Dynamic Sandbox Execution Boundary
- **Unavailable Provider in Local Dev**: In the development environment, the dynamic sandbox provider fails safely (`DYNAMIC_MODEL_UNAVAILABLE`) to strictly prevent executing PE samples on the host OS. Real VM hypervisor detonation requires dedicated physical hardware.

## 3. Deployment & Container Runtime Verification
- **Docker CLI Status**: Host environment lacks Docker CLI (`CommandNotFoundException`). Docker manifests and static container security configurations are `CONFIGURATION VERIFIED` but runtime container deployment is `RUNTIME_VERIFICATION_NOT_PERFORMED`.

## 4. Machine Learning & Ensemble Modeling
- **Baseline Models**: Static ML uses standard Random Forest / XGBoost classifiers; dynamic ML uses a single-layer LSTM. Equal ensemble weighting ($0.5 P_s + 0.5 P_d$) is an engineering baseline heuristic.

## 5. Explainable AI
- **Attribution vs Causality**: SHAP and Captum values indicate feature importance relative to explainer baselines; they do not represent causal proof of maliciousness.
