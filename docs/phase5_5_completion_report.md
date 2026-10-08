# PolyShield AI — Phase 5.5 Completion Report: Provenance Audit & Scientific Classification

> **Phase 5.5 Status**: Complete & Audited.
> **Dataset Version**: `v2.0`
> **Feature Schema Version**: `static-v1`
> **Dataset Provenance Status**: `SYNTHETIC_FIXTURE`
> **Structurally Valid**: `True` (`VALID`)
> **Scientifically Benchmark Ready**: `False` (20 synthetic fixtures)
> **Statistically Powerful**: `False`
> **Dataset Fingerprint**: `4ae9622d1df7c493ecb0ec9ca276e01a88dfad02a64c483a99bc3b63ee2ed85e`

---

## 1. Provenance Audit Summary & Sample Breakdown

- **Verified Real External Samples**: `0`
- **Synthetic Safe Fixtures**: `20`
- **Unverified Provenance Samples**: `0`
- **Audit Findings**: All 20 samples in `data/metadata/source_manifest.csv` are **Category C: Safe PE fixtures created for engineering/testing** (`build_minimal_pe_bytes()`). ZERO samples are real malware binaries acquired from external repositories. Misleading labels claiming external source origin (e.g., MalShare, MalwareBazaar) have been audited and corrected to `synthetic_fixture`.

---

## 2. Dataset Sources & Availability

- **Documented Source Specification**: [`docs/dataset_sources.md`](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/docs/dataset_sources.md)
- **Primary Research Repositories Analyzed**:
  - **EMBER**: Feature-only dataset (vector features extracted from PEs), no raw binaries provided.
  - **SOREL-20M**: Feature records & optional raw PEs downloadable via AWS S3 bucket.
  - **MalwareBazaar**: Raw PE binaries downloadable via authenticated API/ZIP password archive.
  - **PolyShield AI Project Safe PE Fixtures (`source_manifest.csv`)**: 20 minimal PE binaries generated in-memory (`build_minimal_pe_bytes()`) for zero-risk software pipeline validation.

---

## 3. Scientific Benchmark Appropriateness

- **Scientific Evaluation Assessment**: The current 20-sample dataset is **NOT appropriate for real-world scientific malware detection accuracy claims**.
- **Rationale**: The binaries are safe minimal synthetic PE fixtures created to test software pipeline engineering, SHA-256 deduplication, group-aware splitting, and ML classifier ingestion. They do not contain real malicious payloads or complex obfuscated PE structures.
- **Three-Tier Classification**:
  - `structurally_valid`: `True` (Both binary classes present across Train, Validation, and Test splits with zero hash overlap).
  - `scientifically_benchmark_ready`: `False` (Requires $\ge 100$ verified real external binaries).
  - `statistically_powerful`: `False` (Requires $\ge 1000$ real-world PE samples).

---

## 4. 50/50 Class Balance Audit

- **Benign Count**: `10` (50.0%)
- **Malware Count**: `10` (50.0%)
- **Class Ratio**: `1.0000`
- **Audit Conclusion**: The 50/50 balance was **intentionally designed by design** in `data/metadata/source_manifest.csv` as a balanced 1:1 engineering fixture manifest to verify equal-class handling, metric calculations, and XGBoost `scale_pos_weight` calculation without class skew during pipeline development.

---

## 5. Acquisition & Ingestion Pipeline

1. **Manifest Location**: [`data/metadata/source_manifest.csv`](file:///c:/Users/upshu/OneDrive/Desktop/Poly_sheild_ai/data/metadata/source_manifest.csv)
2. **Safe In-Memory Ingestion**: Raw PE bytes read directly from file streams without file execution, double-clicking, or subprocess invocation.
3. **SHA-256 Checksumming**: `SHA256(raw_bytes)` computed directly from file byte contents. Filenames are ignored for identity verification.

---

## 6. Split Statistics & Leakage Analysis

Group-aware splitting (`group_aware=True`, `random_state=42`):

- **Train Split (`train_v2.0.csv`)**: 14 samples (6 benign, 8 malware, `has_both_classes = True`)
- **Validation Split (`validation_v2.0.csv`)**: 3 samples (2 benign, 1 malware, `has_both_classes = True`)
- **Test Split (`test_v2.0.csv`)**: 3 samples (2 benign, 1 malware, `has_both_classes = True`)
- **Leakage Analysis**:
  $$\text{Train} \cap \text{Val} = \emptyset, \quad \text{Train} \cap \text{Test} = \emptyset, \quad \text{Val} \cap \text{Test} = \emptyset$$
  - `0` hash overlap, `0` group ID overlap, `0` family overlap across split boundaries.

---

## 7. Canonical Feature Schema (`static-v1`)

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

---

## 8. Dataset Fingerprint

- **`dataset_fingerprint`**: `4ae9622d1df7c493ecb0ec9ca276e01a88dfad02a64c483a99bc3b63ee2ed85e`
- **Method**: Hashed SHA-256 hex digest of sorted canonical sample SHA-256 hashes, labels, and family metadata.

---

## 9. Security Verification

- **Zero Host File Execution**: Confirmed. All static extraction operates strictly in-memory on raw byte streams via `pefile`. No sample was executed, loaded as executable code, or passed to subprocess commands.
- **Git Exclusion**: `.gitignore` verified blocking `data/raw/*`, `data/samples/*`, `*.exe`, `*.dll`, `*.sys`, `*.scr`, `*.ocx`.

---

## 10. Automated Test Results

Ran:
```powershell
$env:PYTHONPATH="."
.\.venv\Scripts\pytest.exe tests/backend tests/analysis tests/ml
```
**Result**: **50 passed** in 11.55s (100% test pass rate across backend, analysis, and ML test suites).

---

## 11. Frontend Build Result

Ran:
```bash
npm --prefix frontend run build
```
**Result**: Succeeded (`vite v5.4.21 building for production...`, transform complete).

---

## 12. Remaining Limitations & STOP Condition

1. **Synthetic Fixture Scale**: Model performance on `dataset_v2.0` measures pipeline execution validity. Real-world malware detection performance requires ingesting thousands of real PE binaries from SOREL-20M / MalwareBazaar.
2. **Static Scope Limitation**: Static features alone cannot detect dynamic runtime behaviors (e.g. unpacked shellcode, API injection). Dynamic sandbox analysis (Phase 6+) will complement static ML detection.
3. **STOP CONDITION ENFORCED**: Stopped after Phase 5.5 provenance audit & correction. Phase 6 (dynamic sandbox, LSTM, ensemble, SHAP, ML API) is NOT started.

