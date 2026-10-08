# PolyShield AI — 12-Slide Presentation Outline

## Slide 1: Title Slide
- **Title**: PolyShield AI — AI-Powered Polymorphic Malware Detection Platform
- **Subtitle**: Multimodal Machine Learning, Explainable AI, and Security Architecture

## Slide 2: Problem Statement
- Limitations of static hash matching and signature databases against polymorphic malware.
- The challenge of zero-day obfuscation and runtime packing.

## Slide 3: Research Question & Goal
- Research Question: Can invariant structural and behavioral patterns detect polymorphic malware?
- Goal: Build a secure, decoupled, end-to-end malware analysis platform.

## Slide 4: High-Level Architecture
- Architecture diagram (React UI -> Nginx -> FastAPI -> Redis/MongoDB -> Celery Workers).

## Slide 5: Static PE Analysis Modality
- Parsing PE headers, section entropy, RWX flags, and import distributions (`static-v1` 17 features).
- Baseline classifiers: Random Forest & XGBoost.

## Slide 6: Dynamic Behavioral Sequence Modality
- Normalizing event logs into 256-step behavioral sequences.
- PyTorch LSTM model with zero-padding embeddings.

## Slide 7: Multimodal Ensemble & Risk Assessment
- Ensemble probability fusion ($P_{ensemble} = 0.5 P_s + 0.5 P_d$).
- Qualitative risk bands: LOW, MEDIUM, HIGH, CRITICAL.

## Slide 8: Explainable AI (SHAP & Captum)
- SHAP feature importance for static risk indicators.
- Captum LayerIntegratedGradients for behavioral sequence attributions.

## Slide 9: Security Architecture & Host Boundary
- Zero host sample execution policy.
- Safe-root path resolution, JWT auth, RBAC, non-root Docker containers.

## Slide 10: Testing & Verification
- 191 backend tests, 3 frontend tests, 0 unmitigated security findings.

## Slide 11: Honest Disclosures & Limitations
- `dataset_provenance_status = SYNTHETIC_FIXTURE`
- `scientifically_benchmark_ready = false`

## Slide 12: Future Work & Conclusion
- Benchmark evaluation on real-world malware corpora (BODS/EMBER).
- Physical VM sandbox hypervisor integration.
