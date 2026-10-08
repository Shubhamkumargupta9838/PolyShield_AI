import pytest
from pathlib import Path


def test_docker_compose_security_audit():
    compose_path = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    assert compose_path.exists()

    with open(compose_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify docker.sock is NOT mounted
    assert "docker.sock" not in content

    # Verify privileged: true is NOT present
    assert "privileged: true" not in content

    # Verify network_mode: host is NOT present
    assert "network_mode: host" not in content or "network_mode: \"host\"" not in content
