import pytest
from backend.app.core.security import hash_password, verify_password, PBKDF2_ITERATIONS


def test_password_hashing_iterations_and_correctness():
    password = "CorrectSuperPassword2026!"
    hashed = hash_password(password)

    # 1. Correct password verified
    assert verify_password(password, hashed) is True

    # 2. Incorrect password rejected
    assert verify_password("WrongPassword2026!", hashed) is False

    # 3. Hash uses expected format and iteration count
    parts = hashed.split("$")
    assert len(parts) == 4
    assert parts[0] == "pbkdf2_sha256"
    assert int(parts[1]) == 600_000
    assert PBKDF2_ITERATIONS == 600_000


def test_legacy_iteration_hash_verification():
    # Verify legacy 100,000 iteration hashes are correctly verified dynamically
    password = "LegacyUserPassword123!"
    # Manually compute 100k iteration hash
    import hashlib, secrets
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    legacy_hash = f"pbkdf2_sha256$100000${salt.hex()}${key.hex()}"

    assert verify_password(password, legacy_hash) is True
    assert verify_password("WrongLegacyPassword", legacy_hash) is False


def test_malformed_hash_safe_rejection():
    password = "Password123!"

    # Malformed iterations, prefix, or missing fields return False without crashing
    assert verify_password(password, "invalid_hash_string") is False
    assert verify_password(password, "pbkdf2_sha256$notanumber$salt$hash") is False
    assert verify_password(password, "bcrypt$600000$salt$hash") is False
    assert verify_password(password, "") is False


def test_password_never_exposed_in_string_or_repr():
    password = "SecretPassword123!"
    hashed = hash_password(password)

    # Plaintext password is not present in hash output
    assert password not in hashed
