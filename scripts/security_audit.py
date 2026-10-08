#!/usr/bin/env python3
"""
PolyShield AI Static Security Audit Tool (Phase 13).
Performs automated static security scanning across backend, frontend, sandbox, ml, and Docker files.
Produces machine-readable JSON report detailing findings, risk levels, and mitigations.
"""

import os
import re
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

WORKSPACE_ROOT = Path(__file__).resolve().parents[1]

DANGEROUS_PATTERNS = [
    (r"subprocess\.(Popen|run|call|check_output)", "DANGEROUS_SUBPROCESS", "MEDIUM", "Check subprocess usage for command injection or host execution"),
    (r"os\.system\(", "OS_SYSTEM_EXECUTION", "HIGH", "os.system usage detected; potential shell injection risk"),
    (r"os\.popen\(", "OS_POPEN_EXECUTION", "HIGH", "os.popen usage detected; potential shell injection risk"),
    (r"shell\s*=\s*True", "SHELL_TRUE_EXECUTION", "HIGH", "shell=True in subprocess call enables shell expansion"),
    (r"(?<!\.)\beval\(", "UNSAFE_EVAL", "HIGH", "eval() can execute arbitrary code"),
    (r"(?<!\.)\bexec\(", "UNSAFE_EXEC", "HIGH", "exec() can execute arbitrary code"),
    (r"pickle\.loads\(", "UNSAFE_PICKLE", "HIGH", "pickle.loads() can execute arbitrary python code if untrusted"),
    (r"yaml\.load\(", "UNSAFE_YAML", "MEDIUM", "yaml.load without SafeLoader can deserialize arbitrary code"),
    (r"docker\.sock", "DOCKER_SOCKET_MOUNT", "HIGH", "Mounting docker.sock grants host root access"),
    (r"privileged:\s*true", "PRIVILEGED_CONTAINER", "HIGH", "Privileged container bypasses isolation"),
    (r"network_mode:\s*\"?host\"?", "HOST_NETWORK_MODE", "MEDIUM", "Host network mode exposes all host ports"),
    (r"dangerouslySetInnerHTML", "REACT_DANGEROUS_HTML", "MEDIUM", "React innerHTML injection point"),
    (r"allow_origins\s*=\s*\[\s*\"?\*\"?\s*\]", "WILDCARD_CORS", "MEDIUM", "Wildcard CORS origin with credentials"),
]

EXCLUDE_DIRS = {".venv", ".git", ".pytest_cache", "node_modules", "dist", "build", "__pycache__", "docs"}
EXCLUDE_FILES = {"security_audit.py", "test_security_audit.py"}


def run_static_security_audit() -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    scanned_files_count = 0

    for root, dirs, files in os.walk(WORKSPACE_ROOT):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for file_name in files:
            if file_name in EXCLUDE_FILES or file_name.endswith(".pyc"):
                continue

            file_path = Path(root) / file_name
            rel_path = str(file_path.relative_to(WORKSPACE_ROOT))

            # Only scan code files (.py, .js, .jsx, .ts, .tsx, .yml, .yaml, .dockerfile, Dockerfile)
            ext = file_path.suffix.lower()
            if ext not in [".py", ".js", ".jsx", ".ts", ".tsx", ".yml", ".yaml", ".json"] and "Dockerfile" not in file_name:
                continue

            scanned_files_count += 1

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for line_idx, line in enumerate(content.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped.startswith("#") or stripped.startswith("//"):
                        continue

                    for pattern, rule_id, severity, description in DANGEROUS_PATTERNS:
                        if re.search(pattern, line):
                            is_mitigated = False
                            mitigation_reason = ""

                            # Check false-positive mitigations
                            if "pefile" in line or "Static PE Analysis" in line or "MZ" in line:
                                is_mitigated = True
                                mitigation_reason = "In-memory parsing without execution"
                            elif "subprocess" in line and ("mock" in rel_path or "test" in rel_path):
                                is_mitigated = True
                                mitigation_reason = "Mock provider or test patch isolation"
                            elif "docker.sock" in line and ("not in" in line or "deny" in line or "test" in rel_path):
                                is_mitigated = True
                                mitigation_reason = "Negative assertion or security policy definition"
                            elif "privileged" in line and ("not in" in line or "false" in line or "test" in rel_path):
                                is_mitigated = True
                                mitigation_reason = "Negative assertion or non-privileged setting"
                            elif "network_mode" in line and ("not in" in line or "isolated" in line or "test" in rel_path):
                                is_mitigated = True
                                mitigation_reason = "Negative assertion or isolated mode"

                            findings.append({
                                "rule_id": rule_id,
                                "file": rel_path,
                                "line_number": line_idx,
                                "line_snippet": line.strip()[:100],
                                "severity": severity,
                                "description": description,
                                "is_mitigated": is_mitigated,
                                "mitigation_reason": mitigation_reason
                            })
            except Exception as e:
                print(f"[Warning] Failed to scan file '{rel_path}': {e}", file=sys.stderr)

    unmitigated_high = [f for f in findings if f["severity"] == "HIGH" and not f["is_mitigated"]]
    status = "PASS" if len(unmitigated_high) == 0 else "REVIEW_REQUIRED"

    return {
        "status": status,
        "scanned_files_count": scanned_files_count,
        "total_findings_count": len(findings),
        "unmitigated_high_count": len(unmitigated_high),
        "findings": findings
    }


if __name__ == "__main__":
    report = run_static_security_audit()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["status"] == "PASS" else 1)
