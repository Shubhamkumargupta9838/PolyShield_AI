# PolyShield AI — Dataset Sources & Provenance Specification (`docs/dataset_sources.md`)

## Overview

PolyShield AI requires a legitimate, reproducible, and legally compliant benign and malware PE dataset provenance. This document establishes the research repositories, licensing models, access procedures, labeling methodologies, and metadata contracts used by PolyShield AI for static machine learning benchmark experiments (`dataset_v2.0`).

---

## 1. Approved Legitimate Research Repositories

### A. EMBER (Endgame Malware BSER Dataset)
- **Provider**: Elastic / Endgame Security Research
- **Official URL**: [https://github.com/elastic/ember](https://github.com/elastic/ember)
- **License / Usage Terms**: MIT License (Open Open-Source Research License)
- **Publication / Release**: Hyrum S. Anderson and Phil Roth, "EMBER: An Open Dataset for Training Static PE Malware Machine Learning Models", arXiv:1804.07875 (2018).
- **Sample Format**: Extracted PE header metadata & raw PE byte streams.
- **Labeling Methodology**:
  - `0`: Benign (verified via VirusTotal 0-detection and digital signatures from reputable software vendors).
  - `1`: Malware (verified via VirusTotal $\ge 10$ detection engine consensus).
  - `unlabeled`: Excluded from binary benchmark splits.
- **Metadata Fields**: SHA-256, scan date, VirusTotal detection ratio, PE section metadata, import/export tables.

---

### B. SOREL-20M (Sophos-ReSec-L-20M Dataset)
- **Provider**: Sophos AI & ReSec Research Labs
- **Official URL**: [https://github.com/sophos-ai/SOREL-20M](https://github.com/sophos-ai/SOREL-20M)
- **License / Usage Terms**: Creative Commons Attribution 4.0 International (CC BY 4.0)
- **Publication / Release**: Richard Harang and Ethan M. Rudd, "SOREL-20M: A Large Scale Benchmark Dataset for Malicious PE Detection", arXiv:2012.07634 (2020).
- **Sample Format**: 20 million disarmed PE sample features & optional raw PE byte downloads via AWS S3 bucket.
- **Labeling Methodology**:
  - `0`: Benign (signed/verified software binaries).
  - `1`: Malware (detection confirmed by Sophos endpoint detection engine).
- **Metadata Fields**: SHA-256, family tags (`emotet`, `trickbot`, `ransomware`), VirusTotal detection scores, compromise indicators.

---

### C. MalwareBazaar (abuse.ch Ecosystem)
- **Provider**: abuse.ch Research Project
- **Official URL**: [https://bazaar.abuse.ch/](https://bazaar.abuse.ch/)
- **License / Usage Terms**: Open Security Research License (CC0 1.0 Universal)
- **Publication / Release**: Active threat intelligence platform updated daily.
- **Sample Format**: Raw PE binaries (`.exe`, `.dll`, `.sys`) packaged in password-protected ZIP archives (`password: infected`).
- **Labeling Methodology**:
  - `1`: Malware (community & vendor confirmed malware samples).
- **Metadata Fields**: SHA-256, MD5, SHA-1, file size, signature, delivery method, malware family classification (`agent_tesla`, `formbook`, `lokibot`, `remcos`).

---

### D. Microsoft Malware Classification Challenge (Kaggle Dataset)
- **Provider**: Microsoft Defender Research Team
- **Official URL**: [https://www.kaggle.com/c/malware-classification](https://www.kaggle.com/c/malware-classification)
- **License / Usage Terms**: Kaggle Research Competition License
- **Sample Format**: Disarmed PE assembly dumps (`.asm`) and byte sequences (`.bytes`).
- **Labeling Methodology**:
  - 9 distinct malware family classes (`Ramnit`, `Lollipop`, `Kelihos_ver3`, `Vundo`, `Simda`, `Tracur`, `Kelihos_ver1`, `Obfuscator.ACY`, `Gatak`).

---

### E. PolyShield AI Project Safe PE Fixtures (`data/metadata/source_manifest.csv`)
- **Provider**: PolyShield AI Research & Engineering Pipeline
- **Purpose**: Fully reproducible, air-gapped PE engineering test suite containing 20 safe, programmatically generated Windows PE byte structures (`build_minimal_pe_bytes()`) for zero-risk local development, CI/CD, and pipeline verification.
- **License**: MIT License
- **Format**: Valid minimal PE byte buffers in `data/raw/` and metadata records in `data/metadata/source_manifest.csv`.
- **Provenance Status**: `SYNTHETIC_FIXTURE` (`verified_real_sample_count: 0`, `synthetic_sample_count: 20`, `safe_fixture_sample_count: 20`).
- **Data Availability Note**: EMBER provides extracted feature vectors (no raw binaries). SOREL-20M provides feature records and optional raw PEs via AWS S3. MalwareBazaar provides raw PEs via authenticated API/ZIP download. The 20 samples currently included in `source_manifest.csv` are safe synthetic fixtures created for software pipeline validation, NOT real external malware binaries.


---

## 2. Sample Ingestion & Label Integrity Policy

Every sample ingested into `dataset_v2.0` MUST satisfy:

1. **Explicit Binary Target**: $y \in \{0, 1\}$
   - `0` = Benign
   - `1` = Malware
2. **Ambiguous Label Handling**:
   - Samples labeled as `grayware`, `adware`, `PUP` (Potentially Unwanted Program), or `unverified` are **strictly excluded** from binary classification benchmarks to maintain label integrity.
3. **PE Format Validation**:
   - Candidates must pass `pefile` structural validation in memory.
   - Non-PE files or corrupt PE headers set `analysis_status = "INVALID_PE"` and are excluded from model training matrix $X$.
4. **SHA-256 Identity**:
   - Cryptographic hash is computed directly from file bytes: `sha256 = SHA256(raw_bytes)`.
   - File names are treated as arbitrary metadata and never trusted as sample identity.

---

## 3. Dataset Access & Acquisition Model

To ensure security and prevent committing malware to source control:

1. **Git Isolation**: Raw PE binary files (`.exe`, `.dll`, `.sys`, `.scr`, `.ocx`) in `data/raw/` and `data/samples/` are strictly excluded via `.gitignore`.
2. **Reproducible Pipeline**: The repository contains `data/metadata/source_manifest.csv` and the automated CLI dataset builder `python ml/data/build_dataset_cli.py --version v2.0`.
3. **Local Ingestion**: Researchers download or place raw PE binaries into `data/raw/` according to documented provider credentials and run the dataset builder CLI to extract features and construct versioned dataset CSVs.
