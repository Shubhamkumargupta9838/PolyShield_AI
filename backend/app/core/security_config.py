import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class SecuritySettings(BaseSettings):
    """
    Security Settings Schema for PolyShield AI.
    Enforces secure startup validation and prevents implicit insecure defaults.
    """
    AUTH_ENABLED: bool = True
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "polyshield_super_secret_jwt_key_change_in_production_32bytes")
    JWT_ISSUER: str = os.getenv("JWT_ISSUER", "polyshield")
    JWT_AUDIENCE: str = os.getenv("JWT_AUDIENCE", "polyshield-api")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

    # Security Headers Controls
    ENABLE_SECURITY_HEADERS: bool = True
    CONTENT_SECURITY_POLICY: str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
    
    # Rate Limiting Configuration
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_DEFAULT: str = "100/minute"
    RATE_LIMIT_UPLOAD: str = "10/minute"
    RATE_LIMIT_AUTH: str = "30/minute"

    # Model Integrity SHA-256 Hashes
    # Will be computed at runtime or matched against known artifact hashes
    STATIC_MODEL_EXPECTED_SHA256: str = os.getenv("STATIC_MODEL_EXPECTED_SHA256", "")
    DYNAMIC_MODEL_EXPECTED_SHA256: str = os.getenv("DYNAMIC_MODEL_EXPECTED_SHA256", "")

    # Provider Allowlist
    ALLOWED_SANDBOX_PROVIDERS: List[str] = ["mock", "vm"]

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def validate_production_security(self, environment: str, debug: bool):
        """
        Ensures production deployments fail startup if insecure configuration is detected.
        """
        if environment.lower() == "production":
            if debug:
                raise ValueError("SECURITY RISK: DEBUG mode must be False in production!")
            if self.JWT_SECRET_KEY == "polyshield_super_secret_jwt_key_change_in_production_32bytes":
                raise ValueError("SECURITY RISK: Default JWT_SECRET_KEY cannot be used in production!")


security_settings = SecuritySettings()
