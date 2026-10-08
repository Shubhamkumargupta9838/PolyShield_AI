# PolyShield AI — Technical Decision Record (TDR)

## 1. Core Framework Decisions

### Decision 1: FastAPI for Backend Framework
- **Alternatives Considered**: Flask, Django REST Framework.
- **Reason**: FastAPI provides native async/await execution, Pydantic v2 data validation, automated OpenAPI documentation, and sub-millisecond response latency.
- **Trade-off**: Requires careful async DB driver integration (Motor for MongoDB).

### Decision 2: MongoDB for Authoritative State
- **Alternatives Considered**: PostgreSQL, MySQL.
- **Reason**: Scan analysis reports and XAI metadata contain deeply nested dynamic JSON structures (variable-length section lists, import arrays, SHAP arrays) best represented in document collections.
- **Trade-off**: Requires schema validation via Pydantic to prevent unstructured document drift.

### Decision 3: Redis + Celery for Asynchronous Execution
- **Alternatives Considered**: RabbitMQ, Kafka, BackgroundTasks.
- **Reason**: Celery provides task retry policies, timeout management, result backends, and concurrency scaling out of the box with light Redis broker requirements.
- **Trade-off**: Managing Redis task persistence vs ephemeral cache semantics.

---

## 2. Machine Learning Decisions

### Decision 4: Dual-Modality Multimodal Fusion
- **Alternatives Considered**: Single static model, single dynamic model.
- **Reason**: Static PE analysis detects structural indicators instantly without execution overhead; dynamic sequence modeling catches behavioral patterns that bypass static packing. Fusion leverages complementary strengths.
- **Trade-off**: System must handle missing modalities gracefully when dynamic analysis is unavailable.

### Decision 5: PyTorch LSTM for Dynamic Sequences
- **Alternatives Considered**: Transformer (BERT/RoBERTa), 1D-CNN.
- **Reason**: LSTMs capture temporal order across 256-event sequences efficiently with low parameter counts (~64 hidden units), making them suitable for fast inference on CPU environments without GPU requirements.
- **Trade-off**: LSTMs have sequential computation limits compared to parallelized Transformers.

---

## 3. Security Decisions

### Decision 6: Zero Host Sample Execution Invariant
- **Alternatives Considered**: Host-level sandboxing (chroot, bubblewrap).
- **Reason**: Executing untrusted malware samples directly on the primary application host creates catastrophic host compromise risks. Strict byte-stream static parsing and dedicated VM hypervisor boundaries eliminate host infection risk.
- **Trade-off**: Host environment cannot detonate real binaries locally without an isolated physical hypervisor.
