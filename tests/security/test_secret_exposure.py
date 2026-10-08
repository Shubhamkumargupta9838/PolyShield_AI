import pytest
from backend.app.core.security import sanitize_log_input
from backend.app.core.config import settings
from backend.app.core.security_config import security_settings


def test_log_input_sanitization():
    raw_user_input = "malicious_user\nADMIN_GRANT\r\n\x1b[31mRED_TEXT\x1b[0m"
    clean = sanitize_log_input(raw_user_input)

    assert "\n" not in clean
    assert "\r" not in clean
    assert "\x1b" not in clean
    assert "malicious_user" in clean
    assert "ADMIN_GRANT" in clean
    assert "RED_TEXT" in clean


def test_production_security_validation_fails_on_default_secret():
    with pytest.raises(ValueError):
        security_settings.validate_production_security(environment="production", debug=False)
