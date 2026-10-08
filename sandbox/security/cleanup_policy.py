from pydantic import BaseModel, Field


class CleanupPolicy(BaseModel):
    """
    Declarative cleanup policy defining mandatory post-analysis environment destruction rules.
    Guarantees VM snapshot revert / destruction across success, failure, timeout, or crashes.
    """
    auto_destroy_on_completion: bool = Field(True, description="Automatically revert/destroy environment on success")
    auto_destroy_on_failure: bool = Field(True, description="Automatically revert/destroy environment on failure")
    auto_destroy_on_timeout: bool = Field(True, description="Automatically revert/destroy environment on execution timeout")
    verify_destruction: bool = Field(True, description="Enforce explicit post-cleanup status verification check")
    max_cleanup_retries: int = Field(3, ge=1, description="Maximum retries for environment cleanup verification")

    def validate_policy(self) -> bool:
        """Enforces that automatic destruction flags cannot be disabled in production isolation."""
        if not (self.auto_destroy_on_completion and self.auto_destroy_on_failure and self.auto_destroy_on_timeout):
            raise ValueError("CleanupPolicy MUST enforce automatic environment destruction on completion, failure, and timeout.")
        return True
