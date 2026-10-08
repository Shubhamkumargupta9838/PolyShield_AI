# PolyShield AI — Future Research & Engineering Work

## 1. Machine Learning & Dataset Enhancements
- **Real-World Benchmark Evaluation**: Evaluate PolyShield AI on verified real-world malware corpora (e.g., BODS, EMBER, VirusShare) using family-aware splits.
- **Learned Ensemble Weights**: Replace equal-weighted fusion ($0.5 P_s + 0.5 P_d$) with a meta-classifier or calibrated probability model trained on cross-validation data.
- **Advanced Sequence Architectures**: Compare LSTM sequence performance against Transformer-based architectures (e.g., RoBERTa/BERT) for long event sequences.

---

## 2. Dynamic Sandbox Architecture
- **Physical VM Hypervisor Integration**: Deploy physical QEMU/KVM or VirtualBox hypervisors with guest agent instrumentation in dedicated hardware environments.
- **Network Sinkhole & PCAP Parsing**: Integrate isolated network sinkholes to capture dynamic C2 traffic and generate PCAP telemetry.

---

## 3. Operations & Production Observability
- **Managed Secrets & TLS**: Integrate HashiCorp Vault or AWS Secrets Manager and automated Let's Encrypt ACME certificate management.
- **Centralized Telemetry**: Export Prometheus metrics and Grafana dashboards for API response latencies, Celery queue depth, and model inference duration.
