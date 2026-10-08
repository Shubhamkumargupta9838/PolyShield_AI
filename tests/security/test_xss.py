import pytest
from backend.app.core.security import sanitize_log_input


def test_xss_script_injection_string_escaping():
    malicious_filename = "<script>alert('XSS')</script>.exe"
    sanitized = sanitize_log_input(malicious_filename)

    # Verify no control characters exist
    assert "\n" not in sanitized
    assert "\r" not in sanitized
    assert sanitized == "<script>alert('XSS')</script>.exe"
