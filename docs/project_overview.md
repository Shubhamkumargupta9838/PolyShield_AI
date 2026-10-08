# PolyShield AI — Project Overview

## 1. What is PolyShield AI?

**PolyShield AI** is an AI-powered, security-engineered polymorphic malware detection and analysis platform. It combines static Portable Executable (PE) analysis, dynamic behavioral telemetry processing, machine learning (Random Forest, XGBoost, and PyTorch LSTM), multimodal ensemble probability fusion, and Explainable AI (SHAP and Captum) into an isolated, production-packaged security application.

---

## 2. Problem Statement

Traditional signature-based and cryptographic hash-matching malware detection systems struggle against modern polymorphic and metamorphic malware. Polymorphic threats rapidly alter their surface representation (file hashes, section names, byte patterns, and encryption wrappers) while preserving underlying malicious capabilities. As a result, static signature databases frequently fail to detect zero-day variants and newly obfuscated samples.

---

## 3. Core Research Question

> **Can machine-learning models detect polymorphic malware by learning invariant structural and behavioral characteristics rather than relying on conventional signatures or file hashes?**

---

## 4. Technical Solution

PolyShield AI addresses this challenge using a dual-modality multimodal architecture:

1. **Static PE Modality**: Extracts structural characteristics (header flags, section entropy, RWX permissions, API import distributions) and maps them to a canonical 17-feature schema (`static-v1`), evaluated by Random Forest and XGBoost baseline classifiers.
2. **Dynamic Behavioral Modality**: Normalizes execution event streams into a canonical 14-feature aggregate schema (`dynamic-v1`) and a discrete 256-event index sequence evaluated by a PyTorch Recurrent Neural Network (LSTM).
3. **Multimodal Fusion**: Combines static and dynamic predictions using an equal-weighted ensemble baseline ($P_{ensemble} = 0.5 \times P_{static} + 0.5 \times P_{dynamic}$) mapped to qualitative risk bands (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
4. **Explainable AI (XAI)**: Provides human-interpretable feature attributions via TreeExplainer SHAP values for static indicators and Captum LayerIntegratedGradients for behavioral sequence steps.
5. **Security Engineering**: Enforces zero host sample execution, strict safe-root path validation, non-root application containers, and fail-closed security controls.

---

## 5. Engineering vs Scientific Focus

PolyShield AI is designed as both a **security engineering platform** and an **AI/ML system architecture**:
- **Engineering Goal**: Build a complete, production-packaged, end-to-end software architecture with strict security boundaries, asynchronous processing pipelines, non-root containers, and comprehensive automated test suites.
- **Scientific Status**: The project uses safe synthetic fixture datasets for engineering smoke validation. Real-world benchmark validity requires future evaluation on verified real-world malware corpora.
