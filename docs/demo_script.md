# PolyShield AI — 3-Minute Live Demonstration Script

## Overview
This script guides an engineer or presenter through a 3-minute walk-through of PolyShield AI for interviewers, technical leads, or security teams.

---

## Demonstration Flow (3 Minutes)

### Minute 1: Overview & Authentication
1. Open dashboard in browser (`http://localhost:5173`).
2. Point out **PolyShield AI Security Posture** header: JWT auth enforced, host PE execution prohibited, zero unmitigated security findings.
3. Log in using test analyst credentials. Show RBAC role badge (`ANALYST`).

### Minute 2: Sample Upload & Multimodal Analysis
1. Navigate to **Scan Upload** interface.
2. Select safe synthetic demo fixture `tests/fixtures/demo/demo_high_entropy_pe.exe`.
3. Click **Submit Scan**.
4. Show real-time progress tracker:
   - File size & SHA-256 calculation
   - Static PE extraction (17 canonical features)
   - Dynamic telemetry sequence processing
   - Ensemble risk scoring ($P_{ensemble} = 0.5 P_s + 0.5 P_d$)
5. Highlight the resulting **CRITICAL** risk band banner.

### Minute 3: Explainable AI & Security Architecture
1. Scroll to **Static SHAP Attribution Chart**: Point out top risk drivers (elevated section entropy, RWX permission flags, suspicious API imports).
2. Scroll to **Dynamic Sequence Attribution**: Show Captum event step attributions.
3. Open **Security Posture Modal**: Explain trust boundary, zero host execution policy, safe-root path validation, and non-root container deployment.
4. Conclude with honest dataset disclosure: `dataset_provenance_status = SYNTHETIC_FIXTURE`.
