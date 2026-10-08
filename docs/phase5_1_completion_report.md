# PolyShield AI — Phase 5.1 Completion Report: Static ML Baseline Correction & Evaluation Hardening

> **Phase 5.1 Status**: Complete & Verified.
> **Dataset Classification**: `synthetic_fixture`
> **Scientific Benchmark Availability**: `False` (`INSUFFICIENT_CLASS_COVERAGE`)

---

## A. Corrections Made

1. **Dataset Quality Inspector (`ml/data/dataset_quality.py`)**:
   - Implemented `inspect_dataset_quality()` inspecting sample counts, class distributions, unique hashes, and group/family metadata across splits.
   - Evaluates overall `scientific_benchmark_available` (requires both classes in Train, Validation, and Test).
2. **Single-Class Metric Safety Guardrails (`ml/evaluation/metrics.py`)**:
   - For single-class evaluation splits (e.g. Validation/Test splits containing only benign samples):
     - `accuracy` is calculated.
     - `precision`, `recall`, `f1_score`, `roc_auc`, `pr_auc`, `false_negative_rate` are returned as `None` (not fabricated zeroes or 0.5 defaults).
     - Explicit `accuracy_warning` attached stating that accuracy on single-class splits must NOT be interpreted as malware detection capability.
     - Status set to `INSUFFICIENT_CLASS_COVERAGE`.
3. **Model Selection & Evaluation Guardrails (`ml/training/train_static.py`)**:
   - If validation split lacks both classes, `model_selection_status` is flagged as `NOT_SCIENTIFICALLY_EVALUABLE`. Tie-breaker winner is flagged as engineering fallback only.
   - If test split lacks malware, final test evaluation is flagged as `ENGINEERING_SMOKE_EVALUATION`.
   - Added `--strict-evaluation` CLI flag (fails immediately if dataset splits lack binary class coverage).
4. **XGBoost `scale_pos_weight` Consistency (`ml/models/xgboost_model.py`)**:
   - Enforced `scale_pos_weight = num_benign_train / num_malware_train` calculated strictly from `train_v1.0.csv` (`3 / 5 = 0.6`), handling zero denominator edge cases safely.
5. **Enriched Artifact Metadata (`ml/models/model_registry.py`)**:
   - Recorded `evaluation_status`, `dataset_type`, and `scientific_benchmark_available` in `static_baseline_v1.0_metadata.json`.

---

## B. Dataset Quality Audit

- **`train_v1.0.csv`**: 8 samples (3 benign, 5 malware, `has_both_classes = True`)
- **`validation_v1.0.csv`**: 1 sample (1 benign, 0 malware, `has_both_classes = False`)
- **`test_v1.0.csv`**: 1 sample (1 benign, 0 malware, `has_both_classes = False`)

---

## C. Scientific Evaluation Status

> **`EvaluationStatus.INSUFFICIENT_CLASS_COVERAGE`**
>
> **Notice**: Validation and test splits contain no malware samples. The current pipeline run verifies software engineering execution, not scientific malware detection performance.

---

## D. XGBoost Class Weighting

- **Training Benign Count**: `3`
- **Training Malware Count**: `5`
- **Formula**: `scale_pos_weight = num_benign_train / num_malware_train = 3 / 5 = 0.6`
- **Applied `scale_pos_weight`**: `0.6`

---

## E. Metric Safety Audit

For single-class evaluation splits:
- `accuracy`: `1.0` (with explicit warning attached)
- `precision`: `None`
- `recall`: `None`
- `f1_score`: `None`
- `roc_auc`: `None`
- `pr_auc`: `None`
- `false_positive_rate`: `0.0`
- `false_negative_rate`: `None`

---

## F. Model Selection Status

- **Model Selection Status**: `NOT_SCIENTIFICALLY_EVALUABLE`
- **Winner Selected**: `random_forest` (Engineering fallback selection)
- **Locked Threshold**: `0.5`

---

## G. Generated Model Artifacts

Saved under `ml/artifacts/models/`:
- `static_baseline_v1.0.joblib`
- `static_baseline_v1.0_metadata.json`
- `static_baseline_v1.0_metrics.json`
- `environment_v1.0.json`
- `random_forest_feature_importance_v1.0.csv`
- `xgboost_feature_importance_v1.0.csv`

---

## H. Test Suite Results

Ran:
```powershell
$env:PYTHONPATH="."
pytest tests/backend tests/analysis tests/ml
```
**Result**: **42 passed** in 15.01s.

---

## I. Frontend Build Result

Ran:
```bash
npm --prefix frontend run build
```
**Result**: Succeeded (`built in 28.89s`, 2271 modules transformed).

---

## J. Limitations & Disclosures

1. **Fixture Dataset Boundary**: The current 10-sample synthetic baseline fixture is insufficient for scientific benchmark evaluation because validation and test splits contain no malware samples.
2. **Accuracy Caution**: Accuracy = 1.0 on a single-class test set indicates only that benign software was classified as benign. It does not measure or prove malware detection ability.

---

## K. Next Steps

Phase 5.1 is complete. The system is ready for acquisition/integration of a proper benign/malware dataset with balanced class coverage across all splits before treating static ML results as research outcomes.
