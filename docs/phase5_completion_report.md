# PolyShield AI — Phase 5 Completion Report: Static ML Benchmark (Random Forest vs XGBoost)

> **Phase 5 Status**: Complete & Verified (Evaluation Protocol Corrected).
> **Dataset Version**: `v2.0`
> **Feature Schema Version**: `static-v1`
> **Dataset Classification**: `synthetic_fixture`
> **Dataset Provenance Status**: `SYNTHETIC_FIXTURE`
> **Classification Threshold**: `0.5`
> **Model Selection Status**: `NOT_SCIENTIFICALLY_EVALUABLE` (Tied Validation Metrics)
> **Engineering Fallback Model**: `random_forest`
> **Structurally Valid**: `True` (`VALID`)
> **Scientifically Benchmark Ready**: `False` (20 synthetic fixtures)
> **Statistically Powerful**: `False`
> **Dataset Fingerprint**: `4ae9622d1df7c493ecb0ec9ca276e01a88dfad02a64c483a99bc3b63ee2ed85e`

---

## A. Objective

Phase 5 validates the static machine learning training, evaluation, serialization, and comparison pipeline for PolyShield AI using **Random Forest** and **XGBoost** classifiers. 

The evaluation consumes the canonical 17-dimensional `static-v1` feature schema extracted from `dataset_v2.0`. The primary purpose of this run is to verify ML engineering implementation, model artifact governance, thresholding (`threshold = 0.5`), metric safety, and reproducibility on the synthetic engineering fixture dataset.

---

## B. Dataset & Pre-Training Quality Gate

- **Dataset Version**: `v2.0`
- **Dataset Type**: `synthetic_fixture`
- **Provenance Status**: `SYNTHETIC_FIXTURE`
- **Total Sample Count ($N$)**: 20
- **Class Distribution**: 10 Benign (50.0%), 10 Malware (50.0%)
- **Split Distribution** (`group_aware=True`, `random_state=42`):
  - **Train (`train_v2.0.csv`)**: 14 samples (6 benign, 8 malware)
  - **Validation (`validation_v2.0.csv`)**: 3 samples (2 benign, 1 malware)
  - **Test (`test_v2.0.csv`)**: 3 samples (2 benign, 1 malware)
- **Dataset Fingerprint**: `4ae9622d1df7c493ecb0ec9ca276e01a88dfad02a64c483a99bc3b63ee2ed85e`
- **Leakage Analysis**:
  $$\text{Train} \cap \text{Val} = \emptyset, \quad \text{Train} \cap \text{Test} = \emptyset, \quad \text{Val} \cap \text{Test} = \emptyset$$
  - Confirmed 0 SHA-256 hash overlap across all split boundaries.

---

## C. Feature Contract (`static-v1`)

Verified exact 17 canonical features in exact `StaticFeatureVector.feature_names()` ordering ($X.\text{shape}[1] == 17$):

```python
[
    "file_size",                  # 0: PE file size in bytes
    "number_of_sections",         # 1: Number of PE sections
    "dll_count",                  # 2: Number of distinct imported DLLs
    "api_count",                  # 3: Total imported API/function count
    "max_section_entropy",        # 4: Maximum Shannon entropy across sections
    "min_section_entropy",        # 5: Minimum Shannon entropy across sections
    "mean_section_entropy",       # 6: Mean Shannon entropy across sections
    "high_entropy_section_count", # 7: Sections with entropy > 7.0
    "executable_section_count",   # 8: Number of executable sections
    "writable_section_count",     # 9: Number of writable sections
    "rwx_section_count",          # 10: Sections readable, writable, executable
    "unusual_section_count",      # 11: Sections with non-standard names
    "resource_count",             # 12: Number of PE resources
    "suspicious_api_count",       # 13: Imported APIs classified as suspicious
    "static_indicator_count",     # 14: Derived static security indicators
    "is_dll",                     # 15: Whether the binary is a DLL
    "is_driver",                  # 16: Whether the binary is a driver
]
```

Metadata columns (`sample_id`, `filename`, `sha256`, `label`, `family`, `group_id`, `source`) are strictly excluded from input matrix $X$.

---

## D. Random Forest Baseline

- **Library**: `scikit-learn` (`RandomForestClassifier`)
- **Configuration**: `n_estimators=300`, `random_state=42`, `class_weight="balanced"`, `n_jobs=1`
- **Validation Metrics** (Threshold = 0.5):
  - Accuracy: 0.6667, Precision: 0.0000, Recall: 0.0000, F1-Score: 0.0000, ROC-AUC: 0.5000, PR-AUC: 0.6667, FPR: 0.0000, FNR: 1.0000
- **Test Metrics** (Threshold = 0.5, Mode: `ENGINEERING_SMOKE_EVALUATION`):
  - Accuracy: 0.6667, Precision: 0.0000, Recall: 0.0000, F1-Score: 0.0000, ROC-AUC: 0.5000, PR-AUC: 0.6667, FPR: 0.0000, FNR: 1.0000
- **Average Inference Latency**: ~10.9 ms / sample
- **Feature Importance File**: `ml/artifacts/models/random_forest_feature_importance_v2.0.csv`
- **Model Artifact File**: `ml/artifacts/models/random_forest_static_v2.0.joblib`

---

## E. XGBoost Baseline

- **Library**: `xgboost` (`XGBClassifier`)
- **Configuration**: `n_estimators=300`, `max_depth=6`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`, `random_state=42`, `n_jobs=1`
- **Programmatic Class Weighting**: `scale_pos_weight = num_benign_train / num_malware_train = 6 / 8 = 0.75`
- **Validation Metrics** (Threshold = 0.5):
  - Accuracy: 0.6667, Precision: 0.0000, Recall: 0.0000, F1-Score: 0.0000, ROC-AUC: 0.5000, PR-AUC: 0.6667, FPR: 0.0000, FNR: 1.0000
- **Test Metrics** (Threshold = 0.5, Mode: `ENGINEERING_SMOKE_EVALUATION`):
  - Accuracy: 0.6667, Precision: 0.0000, Recall: 0.0000, F1-Score: 0.0000, ROC-AUC: 0.5000, PR-AUC: 0.6667, FPR: 0.0000, FNR: 1.0000
- **Average Inference Latency**: ~1.37 ms / sample
- **Feature Importance File**: `ml/artifacts/models/xgboost_feature_importance_v2.0.csv`
- **Model Artifact File**: `ml/artifacts/models/xgboost_static_v2.0.joblib`

---

## F. Model Selection & Protocol Correction

- **Validation Comparison**:
  Both Random Forest and XGBoost achieved identical validation metrics at `threshold = 0.5` (Validation F1 = 0.0000, Accuracy = 0.6667, ROC-AUC = 0.5000).
- **Model Selection Decision**:
  - `model_selection_status = NOT_SCIENTIFICALLY_EVALUABLE`
  - `model_selection_result = TIED_NOT_EVALUABLE`
  - `engineering_fallback_model = random_forest`
- **Correction Notice**: Neither model is claimed as scientifically superior on this synthetic fixture. Random Forest is serialized as the baseline engineering fallback for pipeline serialization.

---

## G. Scientific Interpretation & Synthetic Data Warning

> **WARNING**:
> This evaluation uses 20 synthetic/safe PE engineering fixtures. The results validate the ML pipeline and implementation only. They must NOT be interpreted as real-world malware detection performance.

Results verify software pipeline engineering execution on safe synthetic PE fixtures, NOT real-world scientific malware detection accuracy.

---

## H. Test-Set Discipline

- **Protocol Verification**: The test set ($N=3$, 2 benign, 1 malware) was evaluated strictly AFTER model training and validation model selection were completed.
- **Single Evaluation**: The test set was never used for hyperparameter tuning, feature selection, or threshold optimization.
- **Evaluation Mode**: `ENGINEERING_SMOKE_EVALUATION`

---

## I. Reproducibility Specs

- **Random Seed**: `42`
- **Environment**: Python 3.12.1, scikit-learn 1.6+, XGBoost 3.4+, NumPy, Pandas (recorded in `ml/artifacts/models/environment_v2.0.json`).
- **CLI Ingestion & Training Commands**:
  ```powershell
  $env:PYTHONPATH="."
  .\.venv\Scripts\python.exe ml/data/build_dataset_cli.py --manifest data/metadata/source_manifest.csv --samples-dir data/raw --version v2.0 --group-aware
  .\.venv\Scripts\python.exe ml/training/train_static.py --version v2.0 --random-state 42
  ```

---

## J. Security Verification

- **Zero Host File Execution**: Confirmed. All static extraction operates strictly in-memory on raw byte streams via `pefile`. No sample was executed, loaded as executable code, or passed to subprocess commands.
- **Git Exclusion**: `.gitignore` verified blocking `data/raw/*`, `data/samples/*`, `*.exe`, `*.dll`, `*.sys`, `*.scr`, `*.ocx`.

---

## K. Fresh Test Suite & Frontend Build Results

### Fresh Automated Test Suite
Ran:
```powershell
$env:PYTHONPATH="."
.\.venv\Scripts\pytest.exe tests/backend tests/analysis tests/ml
```
**Fresh Result**: **50 passed** in 17.23s (100% test pass rate across backend, analysis, and ML test suites).

### Fresh Frontend Production Build
Ran:
```bash
npm --prefix frontend run build
```
**Fresh Result**: Succeeded (`vite v5.4.21 building for production...`, `built in 10.71s`).

---

## L. Limitations & Disclosures

1. **Synthetic Fixture Scale ($N=20$)**: Evaluates software pipeline engineering only. Real-world malware detection claims require a future dataset containing legitimately acquired, provenance-verified external PE samples.
2. **Small Split Sizes**: Train=14, Val=3, Test=3. Insufficient for statistical generalization claims.
3. **Static Scope Limitation**: Static features alone cannot detect dynamic runtime behaviors (e.g. unpacked shellcode, API injection). Dynamic sandbox analysis (Phase 6+) will complement static ML detection.

---

## M. STOP CONDITION

> **Phase 5 is COMPLETE and verified. Phase 6 (dynamic sandbox execution, CAPE, LSTM, ensemble, SHAP, ML API) has NOT been started.**
