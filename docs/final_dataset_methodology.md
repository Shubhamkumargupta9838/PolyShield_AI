# PolyShield AI — Final Dataset Methodology & Provenance Disclosure

## 1. Dataset Provenance Status

```text
dataset_provenance_status = SYNTHETIC_FIXTURE
scientifically_benchmark_ready = false
verified_real_malware_samples = 0
```

---

## 2. Rationale for Synthetic Fixtures

In accordance with strict security invariants and ethical research guidelines:
1. **Zero Host Risk**: Synthetic PE byte streams allow 100% deterministic, non-executable testing across all backend services without risking host compromise or needing isolated physical malware lab hardware.
2. **Reproducible Pipeline Verification**: Synthetic fixtures provide controlled feature variations (e.g., toggling RWX section flags, varying section entropy, adding suspicious API import names) to verify static analyzer extraction, dynamic normalizer event mapping, ML model inference, and XAI attribution pipelines.
3. **Engineering Integrity**: Using synthetic fixtures demonstrates architectural maturity without fabricating fake real-world accuracy numbers.

---

## 3. Distinction: Engineering Validation vs Scientific Benchmark

- **Engineering Smoke Validation (Current State)**: Proves that code compiles, data schema flows end-to-end, REST APIs handle payload validation, Celery tasks execute asynchronously, ML models infer probabilities, and XAI engines compute attributions cleanly without runtime exception.
- **Scientific Benchmark Validation (Future Work)**: Requires training and evaluating models on verified real-world malware corpora (e.g., BODS, VirusShare, Ember) using group-aware family splits and out-of-time evaluation to measure generalization accuracy against unseen polymorphic families.
