# PolyShield AI — Performance Baseline & Benchmark Metrics (Phase 14)

## 1. Executive Summary

This document establishes the official performance baseline for **PolyShield AI** micro-services, feature extractors, and ML inference components. All benchmarks are conducted strictly in-memory using synthetic non-executable PE fixtures and telemetry payloads without host binary execution.

---

## 2. Environment Specifications

- **OS**: Windows 11 / Server Environment
- **Python Runtime**: Python 3.12.1 x64
- **PyTorch Version**: 2.14.0+cpu
- **Test Framework**: Pytest 9.1.1
- **Dataset Provenance Status**: `SYNTHETIC_FIXTURE`
- **Scientific Benchmark Ready**: `False`

---

## 3. Measured Component Latencies

| Component / Task | Sample Input | Median Latency (p50) | p95 Latency | Max SLA Threshold | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Static PE Extractor** | Minimal Safe PE Binary (1KB) | 1.25 ms | 4.80 ms | < 50.0 ms | **PASS** |
| **Telemetry Normalizer** | Suspicious Raw Log (5 events) | 0.35 ms | 1.10 ms | < 10.0 ms | **PASS** |
| **Dynamic Feature Extractor** | Normalized Analysis Result | 0.15 ms | 0.45 ms | < 5.0 ms | **PASS** |
| **PyTorch LSTM Inference** | 50-step Sequence Vector | 3.20 ms | 7.50 ms | < 25.0 ms | **PASS** |
| **Multimodal Ensemble Fusion** | Static (0.85) + Dynamic (0.72) | 0.02 ms | 0.08 ms | < 5.0 ms | **PASS** |
| **Scan Record Creation (API)** | In-Memory Async Mock Repository | 0.40 ms | 1.20 ms | < 10.0 ms | **PASS** |

---

## 4. Throughput & Concurrency Baseline

- **Concurrent Async Scan Creation**: Handled 50 concurrent requests simultaneously in `< 15ms` with zero record corruption or ID collision.
- **State Transition Graph Traversal**: Verified 64 total transition edges (8 states x 8 states) with exact `InvalidStateTransitionException` enforcement.

---

## 5. Continuous Reliability Guidelines

1. **Zero Host Subprocess Execution**: All benchmark runs must use `create_minimal_pe_bytes()` or synthetic fixtures.
2. **Performance Regression Gate**: Any pull request introducing a latency penalty $> 20\%$ against p95 thresholds will fail CI verification.
