# PolyShield AI — Benchmark Methodology (Future Research Specification)

## 1. Objective

This document defines the proposed scientific benchmark protocol for evaluating PolyShield AI against real-world polymorphic malware datasets in future research phases.

---

## 2. Dataset Requirements

To achieve scientific benchmark readiness, future evaluations must acquire:
1. **Real-World Sample Corpora**: Minimum 10,000 verified benign PE binaries and 10,000 verified malware binaries (e.g., EMBER-2018/2020 dataset, VirusShare, BODS).
2. **SHA-256 Deduplication**: Deduplicate samples by cryptographic hash to eliminate exact duplicates across splits.
3. **Family Metadata**: Label malware samples with verified malware family identifiers (e.g., Emotet, TrickBot, WannaCry, CobaltStrike).

---

## 3. Data Splitting Protocol

- **Group-Aware Family Split**: Split samples by malware family rather than random sample selection. Ensures all samples of a given family reside exclusively in `train`, `validation`, or `test`.
- **Temporal Out-of-Time Split**: Train on historical samples (e.g., Year N) and evaluate on future samples (Year N+1) to test resilience against polymorphic evolution.

---

## 4. Benchmark Evaluation Metrics

Target evaluation metrics to be computed on the untouched `test` split:
- **Accuracy**: Overall classification accuracy.
- **Precision & Recall**: Positive predictive value and true positive rate for malware class.
- **F1-Score**: Harmonic mean of precision and recall.
- **ROC-AUC & PR-AUC**: Area under Receiver Operating Characteristic and Precision-Recall curves.
- **False Positive Rate (FPR)**: Target < 0.1% FPR on benign software corpora.
- **Inference Latency**: Median and P95 latency per sample (target < 500ms for static, < 30s for dynamic).
