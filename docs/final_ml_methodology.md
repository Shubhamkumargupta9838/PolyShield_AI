# PolyShield AI — Final Machine Learning Methodology

## 1. Static Modality Methodology
- **Baseline Models**: Random Forest (100 estimators, max depth 12) & XGBoost (learning rate 0.1, max depth 6).
- **Feature Schema**: 17 canonical features (`static-v1`):
  1. `file_size`
  2. `number_of_sections`
  3. `dll_count`
  4. `api_count`
  5. `max_section_entropy`
  6. `min_section_entropy`
  7. `mean_section_entropy`
  8. `high_entropy_section_count`
  9. `executable_section_count`
  10. `writable_section_count`
  11. `rwx_section_count`
  12. `unusual_section_count`
  13. `resource_count`
  14. `suspicious_api_count`
  15. `static_indicator_count`
  16. `is_dll`
  17. `is_driver`

---

## 2. Dynamic Behavioral Modality Methodology
- **Architecture**: PyTorch Recurrent Neural Network (Dynamic LSTM).
- **Hyperparameters**:
  - `embedding_dim` = 64
  - `lstm_units` = 64
  - `dropout` = 0.3
  - `dense_units` = 32 → 1 (Sigmoid output)
  - `max_sequence_length` = 256
  - `padding_idx` = 0 (PAD token zero-vectors)
- **Vocabulary**: 32 canonical behavioral event tokens (`ml/data/dynamic_vocab.py`).

---

## 3. Multimodal Ensemble Fusion
- **Engineering Formula**:
  $$P_{ensemble} = 0.5 \times P_{static} + 0.5 \times P_{dynamic}$$
- **Missing Modality Handling**: If dynamic analysis is unavailable, system gracefully defaults to $P_{ensemble} = P_{static}$ and marks dynamic evaluation status as `DYNAMIC_MODEL_UNAVAILABLE`.
- **Qualitative Risk Band Mapping**:
  - `0.00 – 0.24`: **LOW**
  - `0.25 – 0.49`: **MEDIUM**
  - `0.50 – 0.74`: **HIGH**
  - `0.75 – 1.00`: **CRITICAL**

> **Scientific Disclosure**: Equal 0.5 weighting is an engineering heuristic baseline. It has not been optimized via cross-validation on real-world malware datasets.
