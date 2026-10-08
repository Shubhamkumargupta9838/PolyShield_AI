# PolyShield AI — Multimodal Static + Dynamic Ensemble Model Specification (`docs/ensemble_model.md`)

## 1. Overview & Architectural Objective

Phase 11 introduces the first unified **Multimodal Ensemble Model** (`ensemble_v1.0`) for PolyShield AI, fusing structural static PE analysis probabilities (Random Forest / XGBoost) with dynamic behavioral sequence probabilities (PyTorch LSTM).

```text
               ┌───────────────────────┐
               │     PE Binary Payload │
               └───────────┬───────────┘
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐
│   Static PE Analyzer    │ │ Sandbox Telemetry Trace │
└────────────┬────────────┘ └────────────┬────────────┘
             ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐
│ 17-feature static-v1    │ │ Dynamic Event Sequence  │
└────────────┬────────────┘ └────────────┬────────────┘
             ▼                           ▼
┌─────────────────────────┐ ┌─────────────────────────┐
│ Static Baseline Model   │ │   PyTorch LSTM Model    │
└────────────┬────────────┘ └────────────┬────────────┘
             ▼ P_static                  ▼ P_dynamic
             └─────────────┬─────────────┘
                           ▼
             ┌───────────────────────────┐
             │ Multimodal Ensemble Model │
             │      (ensemble_v1.0)      │
             └─────────────┬─────────────┘
                           ▼ P_ensemble
             ┌───────────────────────────┐
             │ Deterministic Risk Level  │
             │ (LOW/MEDIUM/HIGH/CRITICAL)│
             └───────────────────────────┘
```

---

## 2. Mathematical Ensemble Decision Rule

The default multimodal decision rule uses equal weighting ($w_{\text{static}} = 0.5$, $w_{\text{dynamic}} = 0.5$):

$$P_{\text{ensemble}} = w_{\text{static}} \cdot P_{\text{static}} + w_{\text{dynamic}} \cdot P_{\text{dynamic}}$$

### Decision Boundary
- **Classification**: $\text{malware}$ if $P_{\text{ensemble}} \ge 0.5$, else $\text{benign}$.
- **Threshold Source**: `ENGINEERING_DEFAULT` (0.50).

---

## 3. Explicit Missing Modality Handling

In real-world SOC operations, dynamic execution may be disabled, fail, or be delayed. The ensemble gracefully handles missing modalities without assuming $0.0$ probability (which would falsely imply benign evidence):

| Static Modality ($P_s$) | Dynamic Modality ($P_d$) | Operational Mode (`EnsembleMode`) | Effective Ensemble Formula ($P_{\text{ensemble}}$) |
| :---: | :---: | :---: | :--- |
| **Available** | **Available** | `BOTH_MODALITIES` | $0.5 \cdot P_s + 0.5 \cdot P_d$ |
| **Available** | *Missing* | `STATIC_ONLY` | $P_s$ |
| *Missing* | **Available** | `DYNAMIC_ONLY` | $P_d$ |
| *Missing* | *Missing* | `NONE` | Exception: `PolyShieldException` ("No modality available") |

---

## 4. Dynamic Telemetry Quality Assessment

Dynamic telemetry is evaluated prior to fusion and assigned a `DynamicQualityStatus`:

- `VALID`: Valid trace with sequence length $\ge 2$ and unknown event rate $\le 60\%$.
- `LOW_SIGNAL`: Low-signal trace with high unknown event rate ($> 60\%$) or short sequence ($< 2$ events).
- `INVALID`: Malformed or corrupted trace.
- `UNAVAILABLE`: Dynamic sandbox execution not performed or trace unavailable.

---

## 5. Risk Category Mapping Table

$P_{\text{ensemble}}$ maps deterministically to standardized risk levels:

| $P_{\text{ensemble}}$ Range | Risk Category | Action Recommendation |
| :---: | :---: | :--- |
| $[0.00, 0.25)$ | **LOW** | Allow execution; benign structural & behavioral profile |
| $[0.25, 0.50)$ | **MEDIUM** | Monitor activity; ambiguous structural/behavioral indicators |
| $[0.50, 0.75)$ | **HIGH** | Quarantine binary; high malware likelihood |
| $[0.75, 1.00]$ | **CRITICAL** | Immediate host isolation; confirmed polymorphic malware pattern |

---

## 6. Comparative Ablation Evaluation (`ml/artifacts/ensemble_evaluation_v1.0.json`)

Comparative ablation evaluation on synthetic fixture datasets (`sample_count = 6`):

```json
{
  "dataset_version": "dynamic-v1.0",
  "dataset_provenance_status": "SYNTHETIC_FIXTURE",
  "scientific_benchmark_ready": false,
  "evaluation_status": "ENGINEERING_SMOKE_EVALUATION",
  "ablation_status": "ENGINEERING_ONLY",
  "threshold": 0.5,
  "weights": {
    "static_weight": 0.5,
    "dynamic_weight": 0.5
  },
  "sample_count": 6,
  "models": {
    "static_only": {
      "accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0, "roc_auc": 1.0
    },
    "dynamic_only": {
      "accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0, "roc_auc": 1.0
    },
    "ensemble": {
      "accuracy": 1.0, "precision": 1.0, "recall": 1.0, "f1": 1.0, "roc_auc": 1.0
    }
  },
  "scientific_claim_policy": "The multimodal ensemble has been implemented and engineering-validated. Comparative scientific performance remains unestablished because the current dataset consists of synthetic engineering fixtures and is not benchmark-ready."
}
```

---

## 7. Strict Provenance Disclosures & Non-Claims

> **PROVENANCE DISCLOSURE**: Metrics reflect software pipeline correctness on safe synthetic fixtures. No claims of real-world malware superiority are made without a verified external malware dataset.
