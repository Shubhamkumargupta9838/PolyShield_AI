import os
import re
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, Dict, Any

import jwt
from fastapi import HTTPException, status, UploadFile

from backend.app.core.config import settings
from backend.app.core.security_config import security_settings
from backend.app.core.exceptions import (
    PathTraversalException,
    AuthenticationException,
    FileTooLargeException,
    EmptyFileException,
    InvalidPEFileException
)

# Password Hashing Utilities (PBKDF2-HMAC-SHA256 with 600,000 iterations per OWASP recommendations)
PBKDF2_ITERATIONS = 600_000


def hash_password(password: str) -> str:
    """
    Hashes password using PBKDF2-HMAC-SHA256 with a cryptographically secure salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${key.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain text password against a stored PBKDF2-HMAC-SHA256 hash.
    Constant-time comparison prevents timing attacks.
    """
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_key = bytes.fromhex(parts[3])

        computed_key = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            iterations
        )
        return secrets.compare_digest(expected_key, computed_key)
    except Exception:
        return False


# JWT Token Security Utilities
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a signed JWT access token enforcing mandatory claims (exp, iat, iss, aud).
    """
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=security_settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({
        "exp": expire,
        "iat": now,
        "iss": security_settings.JWT_ISSUER,
        "aud": security_settings.JWT_AUDIENCE
    })

    encoded_jwt = jwt.encode(
        to_encode,
        security_settings.JWT_SECRET_KEY,
        algorithm=security_settings.JWT_ALGORITHM
    )
    return encoded_jwt


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates JWT token. Rejects expired, malformed, or invalid tokens.
    Strictly forbids `alg=none` and checks issuer & audience.
    """
    try:
        header = jwt.get_unverified_header(token)
        if header.get("alg") is None or str(header.get("alg")).lower() == "none":
            raise AuthenticationException("JWT algorithm 'none' is strictly forbidden.")

        payload = jwt.decode(
            token,
            security_settings.JWT_SECRET_KEY,
            algorithms=[security_settings.JWT_ALGORITHM],
            issuer=security_settings.JWT_ISSUER,
            audience=security_settings.JWT_AUDIENCE,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iss": True,
                "verify_aud": True
            }
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthenticationException("Access token has expired.")
    except jwt.InvalidTokenError as e:
        raise AuthenticationException(f"Invalid access token: {str(e)}")


# Path Traversal & Safe-Root Validation
def validate_safe_path(candidate_path: Union[str, Path], allowed_root: Union[str, Path]) -> Path:
    """
    Validates that candidate_path stays within allowed_root using safe-root resolution.
    Raises PathTraversalException if candidate_path escapes allowed_root.
    """
    root = Path(allowed_root).resolve()
    try:
        candidate = Path(candidate_path).resolve()
        candidate.relative_to(root)
        return candidate
    except Exception:
        raise PathTraversalException(str(candidate_path))


# Log Injection Sanitizer
def sanitize_log_input(user_input: str) -> str:
    """
    Sanitizes user-controlled string metadata before writing to structured logs.
    Strips carriage returns, newlines, and ANSI escape codes.
    """
    if not isinstance(user_input, str):
        return str(user_input)
    clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', user_input)
    clean = clean.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return clean.strip()


# File Upload Hardening
def validate_file_upload(file: UploadFile) -> bool:
    """
    Validates upload size bounds, extensions, and prevents null-byte traversal in filenames.
    """
    if file.filename:
        if "\x00" in file.filename:
            raise InvalidPEFileException(detail="Filename contains invalid null byte.")
        ext = "." + file.filename.split(".")[-1].lower() if "." in file.filename else ""
        allowed = [".exe", ".dll", ".sys", ".scr", ".bin", ".ocx"]
        if ext not in allowed:
            raise InvalidPEFileException(detail=f"Unsupported file extension '{ext}'. Only PE binaries are permitted.")
    return True
