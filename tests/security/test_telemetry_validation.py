import pytest
from datetime import datetime, timezone
from sandbox.telemetry.normalizer import TelemetryNormalizer


def test_telemetry_normalizer_sanitizes_untrusted_input():
    normalizer = TelemetryNormalizer()
    now = datetime.now(timezone.utc)

    raw_untrusted = {
        "processes": [
            {"timestamp": now.isoformat(), "pid": 1024, "image_name": "../../../cmd.exe\x00"}
        ]
    }

    result = normalizer.normalize(
        job_id="job_sec_test",
        scan_id="scan_sec_test",
        sample_sha256="a" * 64,
        provider_name="mock",
        environment_id="env_sec_test",
        started_at=now,
        completed_at=now,
        raw_telemetry=raw_untrusted
    )

    assert result.scan_id == "scan_sec_test"
    assert len(result.process_events) >= 1
