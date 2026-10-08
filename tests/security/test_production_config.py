"""
Production Startup Configuration Validation Test Suite (Phase 15).

Verifies that:
1. Setting ENVIRONMENT="production" with DEBUG=True raises ValueError.
2. Setting ENVIRONMENT="production" with default SECRET_KEY or JWT_SECRET_KEY raises ValueError.
3. Setting ENVIRONMENT="production" with wildcard CORS origins raises ValueError.
"""

import pytest
from backend.app.core.config import Settings
from backend.app.core.security_config import SecuritySettings


def test_production_config_rejects_debug_mode():
    """Verify production environment fails if DEBUG is True."""
    s = Settings(ENVIRONMENT="production", DEBUG=True)
    with pytest.raises(ValueError) as exc_info:
        s.validate_production_config()
    assert "DEBUG mode must be False in production" in str(exc_info.value)


def test_production_config_rejects_default_secret_key():
    """Verify production environment fails if default SECRET_KEY is used."""
    s = Settings(ENVIRONMENT="production", DEBUG=False, SECRET_KEY="polyshield_super_secret_key_change_in_production")
    with pytest.raises(ValueError) as exc_info:
        s.validate_production_config()
    assert "Default SECRET_KEY cannot be used in production" in str(exc_info.value)


def test_production_config_rejects_wildcard_cors():
    """Verify production environment fails if wildcard '*' is in CORS_ORIGINS."""
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        SECRET_KEY="a_strong_production_secret_key_1234567890",
        CORS_ORIGINS=["*"]
    )
    with pytest.raises(ValueError) as exc_info:
        s.validate_production_config()
    assert "Wildcard '*' in CORS_ORIGINS is prohibited in production" in str(exc_info.value)


def test_production_security_settings_rejects_default_jwt_secret():
    """Verify SecuritySettings fails if default JWT_SECRET_KEY is used in production."""
    sec = SecuritySettings(JWT_SECRET_KEY="polyshield_super_secret_jwt_key_change_in_production_32bytes")
    with pytest.raises(ValueError) as exc_info:
        sec.validate_production_security(environment="production", debug=False)
    assert "Default JWT_SECRET_KEY cannot be used in production" in str(exc_info.value)
