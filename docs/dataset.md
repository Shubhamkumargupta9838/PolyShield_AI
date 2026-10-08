# PolyShield AI — Dataset Pipeline & Specification (`docs/dataset.md`)

## Overview

The PolyShield AI Dataset Pipeline (Phase 4 & Phase 5.1) is a clean, reproducible, validated, versioned, and leakage-resistant data engineering pipeline. It transforms Portable Executable (PE) binaries into standard tabular datasets containing the canonical 17-dimensional static feature vector (`static-v1`) for machine learning models.

---

## 1. Canonical Feature Vector Schema (`static-v1`)

The dataset pipeline enforces the exact 17-feature canonical vector schema bound directly to `StaticFeatureVector.feature_names()`. All feature values are non-null numerical values (`float64`).

| Feature Index | Feature Name | Description | Range / Unit |
| :---: | :--- | :--- | :--- |
| **0** | `file_size` | PE file size in bytes (Feature #1) | Bytes ($\ge 0$) |
| **1** | `number_of_sections` | Number of PE sections | Count ($\ge 0$) |
| **2** | `dll_count` | Number of distinct imported DLLs | Count ($\ge 0$) |
| **3** | `api_count` | Total imported API/function count | Count ($\ge 0$) |
| **4** | `max_section_entropy` | Maximum Shannon entropy across sections | Bits per byte ($0.0 \le e \le 8.0$) |
| **5** | `min_section_entropy` | Minimum Shannon entropy across sections | Bits per byte ($0.0 \le e \le 8.0$) |
| **6** | `mean_section_entropy` | Mean Shannon entropy across sections | Bits per byte ($0.0 \le e \le 8.0$) |
| **7** | `high_entropy_section_count` | Number of sections exceeding high-entropy threshold ($> 7.0$) | Count ($\ge 0$) |
| **8** | `executable_section_count` | Number of executable sections | Count ($\ge 0$) |
| **9** | `writable_section_count` | Number of writable sections | Count ($\ge 0$) |
| **10** | `rwx_section_count` | Number of sections simultaneously readable, writable, and executable | Count ($\ge 0$) |
| **11** | `unusual_section_count` | Number of sections with non-standard section names | Count ($\ge 0$) |
| **12** | `resource_count` | Number of PE resources | Count ($\ge 0$) |
| **13** | `suspicious_api_count` | Number of imported APIs classified as suspicious by Phase 3 rules | Count ($\ge 0$) |
| **14** | `static_indicator_count` | Number of derived static security indicators | Count ($\ge 0$) |
| **15** | `is_dll` | Whether the PE is a DLL ($1.0$ or $0.0$) | Boolean |
| **16** | `is_driver` | Whether the PE is identified as a driver ($1.0$ or $0.0$) | Boolean |

### Metadata Fields (Excluded from Model Input Matrix $X$)
The raw dataset DataFrame retains sample metadata for provenance, auditing, and leak-free splitting. These fields are **never** included in feature matrix $X$:
* `sample_id`: Unique identifier assigned during build
* `filename`: Original binary filename
* `sha256`: Cryptographic SHA-256 hash
* `label`: Supervised target ($0 = \text{benign}, 1 = \text{malware}$)
* `label_name`: Human-readable label string
* `family`: Malware family name (e.g., `emotet`, `wannacry`)
* `group_id`: Shared cluster/variant group identifier
* `source`: Data source provenance (e.g., `synthetic`, `malshare`)
* `analysis_success`: Boolean analysis success status flag
* `analysis_error`: Error message string if analysis failed
* `dataset_version`: Dataset version tag (`v1.0`)
* `feature_schema_version`: Feature schema version (`static-v1`)

---

## 2. Dataset Versioning & Governance

PolyShield AI implements explicit schema and dataset versioning:

* **Feature Schema Version (`static-v1`)**: Identifies the 17-feature structure, column names, and extraction logic. Any change to the 17 features requires bumping the schema version tag.
* **Dataset Version (`v1.0`)**: Tag representing a specific snapshot of samples, manifest records, and generated splits.

---

## 3. Manifest Structure & Data Ingestion

The dataset builder ingests samples via CSV manifests.

```csv
filename,label,family,group_id,source
benign_sample_001.exe,0,,,synthetic
malware_sample_001.exe,1,family_alpha,group_a,dataset_x
```

### Parsing & Safe Analysis Pipeline
1. Reads manifest entries.
2. Reads target binary bytes strictly from disk without executing the file.
3. Invokes Phase 3 `StaticFeatureExtractor` in-memory.
4. Computes SHA-256 hash.
5. Populates `analysis_success` ($True$) and feature vector values, or logs `analysis_error` ($False$) if corrupt/unparseable PE.

---

## 4. Validation Engine & Quality Assurance

Every dataset undergoes automated validation prior to machine learning operations:

1. **Schema Integrity**: Validates that all 17 canonical feature columns are present and non-null.
2. **Numeric Safety**: Guarantees zero `NaN`, `null`, or `Inf` values across feature columns.
3. **Logical Bounds Verification**:
   * Entropy bounds: $0.0 \le e \le 8.0$.
   * Section count bounds: `min_section_entropy` / `max_section_entropy` consistency vs `number_of_sections`.
4. **Failure Handling**: Failed PE analyses are retained with `analysis_success=False` and isolated from training matrix $X$.
5. **SHA-256 Deduplication**: Identifies and removes exact duplicate file hashes (`sha256`) within the dataset to prevent exact-file duplicate leakage across splits.

---

## 5. Leakage Prevention & Splitting Strategy

### Zero-Hash Leakage Boundary
A standard random split can cause data leakage if identical binaries exist under different filenames. PolyShield AI groups samples by unique cryptographic hash (`sha256`) prior to split allocation, guaranteeing:
$$\text{Train} \cap \text{Val} = \emptyset, \quad \text{Train} \cap \text{Test} = \emptyset, \quad \text{Val} \cap \text{Test} = \emptyset$$

### Group-Aware Splitting & Limitations
When reliable family/group metadata is available, group-aware splitting (`group_aware=True`) keeps samples belonging to the same known group/family within a single split, reducing family-level leakage. This does not guarantee detection or isolation of every polymorphic variant because family metadata may be incomplete or incorrect.

### Default Split Ratios
* **Train**: 70%
* **Validation**: 15%
* **Test**: 15%

---

## 6. Requirements for Scientific ML Benchmark & Provenance Audit

To establish a scientifically valid malware detection benchmark (rather than a pipeline engineering fixture), a dataset MUST satisfy:

1. **Dataset Provenance Status (`dataset_provenance_status`)**:
   - `VERIFIED_REAL_EXTERNAL_DATA`: All samples acquired from documented external repositories with verified hashes.
   - `MIXED_REAL_AND_SYNTHETIC`: Combination of real external binaries and synthetic test fixtures.
   - `SYNTHETIC_FIXTURE`: Programmatically generated safe PE fixtures created for pipeline validation (e.g. `dataset_v2.0`).
   - `UNVERIFIED_PROVENANCE`: Samples lacking verifiable external acquisition metadata.

2. **Three-Tier Scientific Benchmark Distinction**:
   - `structurally_valid`: Both binary classes ($y=0$ and $y=1$) present across Train, Validation, and Test splits with zero hash overlap.
   - `scientifically_benchmark_ready`: `structurally_valid` AND `VERIFIED_REAL_EXTERNAL_DATA` status AND total samples $\ge 100$.
   - `statistically_powerful`: `scientifically_benchmark_ready` AND total samples $\ge 1000$.

3. **Current Dataset Classification (`dataset_v2.0`)**:
   - **Provenance Status**: `SYNTHETIC_FIXTURE`
   - **Verified Real Samples**: 0
   - **Synthetic Safe Fixtures**: 20
   - **Unverified Samples**: 0
   - **Structurally Valid**: `True`
   - **Scientifically Benchmark Ready**: `False` (20 synthetic fixtures only)
   - **Statistically Powerful**: `False`
   - **Notice**: Results verify software pipeline engineering execution only, NOT real-world malware detection performance.

---

## 7. Dataset Artifacts & CLI Usage

Dataset builds generate timestamped and versioned artifacts saved to `ml/artifacts/dataset/`:
* `dataset_v1.0.csv`: Full validated dataset
* `train_v1.0.csv`: Training split (70%)
* `validation_v1.0.csv`: Validation split (15%)
* `test_v1.0.csv`: Test split (15%)
* `dataset_report_v1.0.json`: Detailed validation and balance metadata report

### Generating Dataset via CLI

To build and validate the dataset using default configurations:

```powershell
$env:PYTHONPATH="."
python ml/data/build_dataset_cli.py --manifest ml/data/manifests/manifest.csv --samples-dir data/samples --version v1.0
```

To enable group-aware family splitting:

```powershell
python ml/data/build_dataset_cli.py --group-aware --version v1.0
```
