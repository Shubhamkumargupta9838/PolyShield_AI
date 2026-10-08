from pydantic import BaseModel, Field


class ResourcePolicy(BaseModel):
    """
    Declarative resource containment policy enforcing execution boundaries and limits.
    """
    cpu_limit_cores: float = Field(2.0, gt=0, description="Maximum CPU cores allocated to guest VM")
    memory_limit_mb: int = Field(4096, gt=0, description="Maximum RAM allocated to guest VM in MB")
    disk_limit_mb: int = Field(20480, gt=0, description="Maximum disk space allocated in MB")
    timeout_seconds: int = Field(300, gt=0, description="Maximum execution timeout in seconds")
    max_process_count: int = Field(100, gt=0, description="Maximum simultaneous process count allowed in guest")
    max_artifact_size_mb: int = Field(500, gt=0, description="Maximum total artifact storage size allowed per job")
    max_network_bytes: int = Field(50 * 1024 * 1024, ge=0, description="Maximum network traffic limit in bytes")

    def validate_policy(self) -> bool:
        """Validates resource boundary settings."""
        if self.timeout_seconds <= 0 or self.timeout_seconds > 3600:
            raise ValueError("ResourcePolicy timeout_seconds must be between 1 and 3600 seconds.")
        if self.memory_limit_mb < 512 or self.memory_limit_mb > 65536:
            raise ValueError("ResourcePolicy memory_limit_mb must be between 512MB and 65536MB.")
        return True
