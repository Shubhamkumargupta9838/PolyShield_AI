import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from backend.app.core.security_config import security_settings


class Settings(BaseSettings):
    PROJECT_NAME: str = "PolyShield AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "polyshield_super_secret_key_change_in_production")

    API_V1_PREFIX: str = "/api/v1"
    BACKEND_HOST: str = os.getenv("BACKEND_HOST", "0.0.0.0")
    BACKEND_PORT: int = int(os.getenv("BACKEND_PORT", "8000"))

    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]

    MONGODB_URL: str = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    MONGODB_DB_NAME: str = os.getenv("MONGODB_DB_NAME", "polyshield_db")

    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")
    CELERY_TASK_ALWAYS_EAGER: bool = os.getenv("CELERY_TASK_ALWAYS_EAGER", "False").lower() in ("true", "1")
    WORKER_CONCURRENCY: int = int(os.getenv("WORKER_CONCURRENCY", "4"))
    WORKER_TASK_TIMEOUT_SECONDS: int = int(os.getenv("WORKER_TASK_TIMEOUT_SECONDS", "300"))

    LOG_FORMAT: str = os.getenv("LOG_FORMAT", "JSON")
    MAX_UPLOAD_SIZE_BYTES: int = 52428800  # 50 MB

    # Phase 8 Sandbox Security & Isolation Settings
    SANDBOX_PROVIDER: str = os.getenv("SANDBOX_PROVIDER", "mock")
    SANDBOX_TIMEOUT_SECONDS: int = int(os.getenv("SANDBOX_TIMEOUT_SECONDS", "300"))
    SANDBOX_MAX_MEMORY_MB: int = int(os.getenv("SANDBOX_MAX_MEMORY_MB", "4096"))
    SANDBOX_MAX_DISK_MB: int = int(os.getenv("SANDBOX_MAX_DISK_MB", "20480"))
    SANDBOX_MAX_ARTIFACT_SIZE_MB: int = int(os.getenv("SANDBOX_MAX_ARTIFACT_SIZE_MB", "500"))
    SANDBOX_INTERNET_ACCESS: bool = os.getenv("SANDBOX_INTERNET_ACCESS", "False").lower() in ("true", "1")
    SANDBOX_NETWORK_MODE: str = os.getenv("SANDBOX_NETWORK_MODE", "isolated")

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    def validate_production_config(self) -> None:
        """
        Validates environment configuration during startup.
        Fails startup if ENVIRONMENT is production and insecure secrets or settings are present.
        """
        if self.ENVIRONMENT.lower() == "production":
            if self.DEBUG:
                raise ValueError("SECURITY RISK: DEBUG mode must be False in production!")
            if self.SECRET_KEY == "polyshield_super_secret_key_change_in_production":
                raise ValueError("SECURITY RISK: Default SECRET_KEY cannot be used in production!")
            if "*" in self.CORS_ORIGINS:
                raise ValueError("SECURITY RISK: Wildcard '*' in CORS_ORIGINS is prohibited in production!")
            security_settings.validate_production_security(self.ENVIRONMENT, self.DEBUG)


settings = Settings()
