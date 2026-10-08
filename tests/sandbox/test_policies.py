import pytest
from sandbox.security.isolation_policy import IsolationPolicy
from sandbox.security.network_policy import NetworkPolicy
from sandbox.security.resource_policy import ResourcePolicy
from sandbox.security.cleanup_policy import CleanupPolicy


def test_isolation_policy_defaults_and_validation():
    policy = IsolationPolicy()
    assert policy.deny_host_filesystem is True
    assert policy.deny_host_processes is True
    assert policy.deny_docker_socket is True
    assert policy.deny_shared_folders is True
    assert policy.deny_shared_clipboard is True
    assert policy.deny_usb_passthrough is True
    assert policy.deny_secret_access is True
    assert policy.validate_policy() is True

    # Test invalid modification rejection
    with pytest.raises(ValueError, match="MUST be True"):
        invalid_policy = IsolationPolicy(deny_host_filesystem=False)
        invalid_policy.validate_policy()


def test_network_policy_defaults_and_validation():
    policy = NetworkPolicy()
    assert policy.internet_access is False
    assert policy.network_mode == "isolated"
    assert policy.dns_policy == "sinkhole"
    assert policy.validate_policy() is True

    # Test invalid configuration rejection
    with pytest.raises(ValueError, match="internet_access cannot be True"):
        invalid_policy = NetworkPolicy(internet_access=True, network_mode="isolated")
        invalid_policy.validate_policy()


def test_resource_policy_defaults_and_validation():
    policy = ResourcePolicy()
    assert policy.cpu_limit_cores == 2.0
    assert policy.memory_limit_mb == 4096
    assert policy.disk_limit_mb == 20480
    assert policy.timeout_seconds == 300
    assert policy.validate_policy() is True

    with pytest.raises(ValueError):
        ResourcePolicy(timeout_seconds=0)


def test_cleanup_policy_defaults_and_validation():
    policy = CleanupPolicy()
    assert policy.auto_destroy_on_completion is True
    assert policy.auto_destroy_on_failure is True
    assert policy.auto_destroy_on_timeout is True
    assert policy.validate_policy() is True

    with pytest.raises(ValueError, match="MUST enforce automatic environment destruction"):
        invalid_policy = CleanupPolicy(auto_destroy_on_completion=False)
        invalid_policy.validate_policy()
