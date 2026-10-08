# PolyShield AI — Explainable AI (XAI) Architecture

## 1. Overview

PolyShield AI integrates dual-modality Explainable AI to provide security analysts with clear, defensible explanations for automated malware risk classifications.

---

## 2. Static Feature Attribution (SHAP)
- **Engine**: `shap.TreeExplainer` applied to Random Forest / XGBoost models.
- **Interpretation**: Computes exact Shapley values for each of the 17 static features (`static-v1`).
- **Analyst View**: Identifies top risk-increasing indicators (e.g., elevated `rwx_section_count`, `max_section_entropy > 7.2`, `suspicious_api_count > 5`) versus benign indicators.

---

## 3. Dynamic Sequence Attribution (Captum)
- **Engine**: Captum `LayerIntegratedGradients` applied to PyTorch LSTM embedding layer.
- **Interpretation**: Calculates integrated gradients per discrete event step across the 256-event execution sequence.
- **Analyst View**: Highlights specific high-attribution behavioral sequences (e.g., `PROCESS_CREATE` followed by `REGISTRY_SET_VALUE` and `NETWORK_CONNECT`).

---

## 4. Distinction: Observed Evidence vs Model Attribution

> **Critical Principle**: XAI attributions quantify how input features influence the model's numerical output relative to a baseline. They do NOT constitute causal proof of malicious intent.

- **Observed Evidence**: Verifiable structural properties extracted directly from PE bytes (e.g., Section `.text` has permissions `0xE0000020` RWX; API `VirtualProtect` imported).
- **Model Attribution**: Mathematical SHAP / Integrated Gradients values showing how much that feature shifted the predicted probability toward `MALWARE`.
