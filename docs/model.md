# PolyShield AI — Static ML Baseline Model Specification (`docs/model.md`)

## 1. Overview & Objective

Phase 5, Phase 5.5, and Phase 6 establish and integrate the static machine-learning baseline for PolyShield AI using the canonical 17-dimensional `static-v1` feature vector and versioned dataset artifacts (`v1.0` and `v2.0`).

The primary research objective is to evaluate how effectively the canonical 17 static structural PE features distinguish benign Windows executables from malware binaries prior to sandbox execution, and integrate the baseline model into the end-to-end FastAPI scan service.

---

## 2. Canonical 17-Feature Schema (`static-v1`)

Model training and online inference consume the exact 17 features bound directly to `StaticFeatureVector.feature_names()`:

1. `file_size`: PE file size in bytes (Feature #1 in matrix $X$).
2. `number_of_sections`: Number of PE section headers.
3. `dll_count`: Count of distinct imported Dynamic Link Libraries (DLLs).
4. `api_count`: Total imported Win32 API functions count.
5. `max_section_entropy`: Maximum Shannon entropy across sections ($0.0 \le e \le 8.0$).
6. `min_section_entropy`: Minimum Shannon entropy across sections ($0.0 \le e \le 8.0$).
7. `mean_section_entropy`: Mean Shannon entropy across sections ($0.0 \le e \le 8.0$).
8. `high_entropy_section_count`: Count of sections exceeding high-entropy threshold ($> 7.0$).
9. `executable_section_count`: Count of executable sections.
10. `writable_section_count`: Count of writable sections.
11. `rwx_section_count`: Count of sections simultaneously readable, writable, and executable.
12. `unusual_section_count`: Count of non-standard section names.
13. `resource_count`: Count of PE resources.
14. `suspicious_api_count`: Count of security-sensitive Win32 APIs imported.
15. `static_indicator_count`: Count of derived static security indicators.
16. `is_dll`: Binary flag ($1.0$ if DLL, $0.0$ otherwise).
17. `is_driver`: Binary flag ($1.0$ if System Driver, $0.0$ otherwise).

> **Metadata Exclusion**: Identifiers (`sample_id`, `filename`, `sha256`, `family`, `group_id`), status flags (`analysis_success`, `analysis_error`), and target labels (`label`) are strictly excluded from input matrix $X$.

---

## 3. Model Baseline Configurations

### Random Forest Baseline (`RandomForestBaseline`)
- **Library**: `scikit-learn` (`RandomForestClassifier`)
- **Hyperparameters**: `n_estimators=300`, `random_state=42`, `class_weight="balanced"`, `n_jobs=1`
- **Class Weighting**: Balanced sample weighting strictly derived from training split.

### XGBoost Baseline (`XGBoostBaseline`)
- **Library**: `xgboost` (`XGBClassifier`)
- **Hyperparameters**: `n_estimators=300`, `max_depth=6`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`, `scale_pos_weight=0.75`, `random_state=42`, `n_jobs=1`, `eval_metric="logloss"`
- **Scale Pos Weight**: Calculated strictly from training split: `scale_pos_weight = num_benign / num_malware = 6 / 8 = 0.75`.

---

## 4. Leakage Prevention & Train/Val/Test Methodology

- **Training**: Fitted exclusively on `train_v2.0.csv`.
- **Validation**: Evaluated exclusively on `validation_v2.0.csv` for hyperparameter inspection and classification threshold selection.
- **Untouched Test Set**: `test_v2.0.csv` remains strictly untouched during model comparison and threshold tuning, and is evaluated ONCE on the locked winning model.

---

## 5. Security Evaluation Metrics & Results (`dataset_v2.0`)

### Primary Selection Metric: F1-Score

Validation performance comparison on `dataset_v2.0` (`structurally_valid = True`, `dataset_provenance_status = SYNTHETIC_FIXTURE`, `scientifically_benchmark_ready = False`):

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | PR-AUC | FPR | FNR | Threshold | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Val)** | 0.6667 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.6667 | 0.0000 | 1.0000 | 0.5000 | `NOT_SCIENTIFICALLY_EVALUABLE` |
| **XGBoost (Val)** | 0.6667 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.6667 | 0.0000 | 1.0000 | 0.5000 | `NOT_SCIENTIFICALLY_EVALUABLE` |

### Final Test Evaluation (`threshold = 0.5`, Mode: `ENGINEERING_SMOKE_EVALUATION`)
- **Random Forest (Test)**: Accuracy: 0.6667, Precision: 0.0000, Recall: 0.0000, F1: 0.0000, ROC-AUC: 0.5000, PR-AUC: 0.6667, Latency: ~10.9 ms
- **XGBoost (Test)**: Accuracy: 0.6667, Precision: 0.0000, Recall: 0.0000, F1: 0.0000, ROC-AUC: 0.5000, PR-AUC: 0.6667, Latency: ~1.37 ms
- **Model Selection Decision**: `model_selection_status = NOT_SCIENTIFICALLY_EVALUABLE` (RF and XGBoost tied; RF serialized as `engineering_fallback_model`).
- **Provenance Notice**: Results verify software pipeline engineering execution on safe synthetic PE fixtures, NOT real-world scientific detection accuracy.

---

## 6. Model Artifact Governance & Versioning

Serializations are saved under `ml/artifacts/models/`:
- `static_baseline_v2.0.joblib`: Serialized model weights (`static_baseline_v2.0`).
- `static_baseline_v2.0_metadata.json`: Model version (`static-baseline-v1`), dataset version (`v2.0`), schema version (`static-v1`), hyperparameters, threshold (0.5), sample counts, evaluation status (`VALID`), dataset type (`synthetic_fixture`), provenance status (`SYNTHETIC_FIXTURE`), structurally valid (`true`), scientifically benchmark ready (`false`), and timestamp.
- `static_baseline_v2.0_metrics.json`: Validation comparison and final test metrics JSON.

---

## 7. Model Loading Service Abstraction (`ModelService`)

Phase 6 introduces a dedicated model loading abstraction (`backend/app/services/model_service.py`):

1. **Singleton Initialization**: Loads `static_baseline_v2.0.joblib` and `static_baseline_v2.0_metadata.json` once during startup.
2. **Contract Validation**:
   - `dataset_version == "v2.0"`
   - `feature_schema_version == "static-v1"`
   - `feature_count == 17`
   - `feature_names == StaticFeatureVector.feature_names()`
   - `classification_threshold == 0.5`
3. **Inference Logic**: Consumes 17-dimensional `StaticFeatureVector`, computes $P(\text{malware})$ and $P(\text{benign})$, and returns structured output containing prediction label, score probabilities, threshold, and mandatory synthetic model warning notices.

---

## 8. Known Security Limitations & Disclosures

1. **Static Analysis Limitation**: The static model learns strictly from structural PE attributes. It does not observe runtime behavioral execution and cannot establish behavioral equivalence or guarantee complete detection of obfuscated/polymorphic malware.
2. **Synthetic Dataset Limitation**: The baseline model was trained using 20 synthetic/safe PE fixtures. Output scores must be represented as engineering evaluation model probabilities rather than calibrated real-world malware certainty.

---

## 9. Multimodal Static + Dynamic Ensemble Model (`ensemble_v1.0`)

For complete details on the Phase 11 multimodal static structural + dynamic sequence probability fusion model, missing modality handling, quality gating, and comparative ablation metrics, see [docs/ensemble_model.md](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/ensemble_model.md).

---

## 10. Explainable AI (XAI) & Attribution Model (`explanation_v1.0`)

Phase 12 integrates local attribution explainers for static, dynamic, and ensemble modalities:

1. **Static SHAP Explainer (`StaticSHAPExplainer`)**:
   - `shap.TreeExplainer` applied to `static_baseline_v2.0.joblib`.
   - Strictly aligned with 17 canonical features.
   - Enforces additive sanity property: $\text{base\_value} + \sum \phi_i \approx P_{\text{static}}$.

2. **Dynamic Sequence Explainer (`DynamicSequenceExplainer`)**:
   - `captum.attr.LayerIntegratedGradients` applied to PyTorch LSTM embedding layer.
   - `<PAD>` (token 0) excluded from attributions; `<UNK>` (token 1) preserved.
   - Occlusion fallback for gradient integration exceptions.

3. **Ensemble Component Explainer (`EnsembleExplainer`)**:
   - Decomposes equal-weight fusion ($0.5 \times P_{\text{static}} + 0.5 \times P_{\text{dynamic}}$) into component contributions.

For detailed architecture, non-causal policies, and API specifications, see [docs/explainability.md](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/explainability.md).
