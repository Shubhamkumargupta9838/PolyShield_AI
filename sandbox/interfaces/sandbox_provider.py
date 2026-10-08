from abc import ABC, abstractmethod
from typing import List, Optional
from sandbox.models.sandbox_job import SandboxJob, SandboxJobStatus
from sandbox.models.artifact import SandboxArtifact


class ISandboxProvider(ABC):
    """
    Abstract Base Class / Interface for Sandbox Providers.
    Defines mandatory lifecycle management, artifact collection, and cleanup contracts.
    Must be implemented by concrete providers (e.g. MockSandboxProvider).
    """

    @abstractmethod
    def create_environment(self, job: SandboxJob) -> str:
        """
        Allocates and prepares an isolated sandbox environment (e.g. guest VM / container).
        Returns environment_id string identifier.
        """
        pass

    @abstractmethod
    def submit_sample(self, environment_id: str, sample_sha256: str) -> bool:
        """
        Transfers sample reference metadata to isolated environment boundary.
        MUST NOT perform binary execution.
        """
        pass

    @abstractmethod
    def start_analysis(self, environment_id: str) -> bool:
        """
        Initiates analysis lifecycle in environment.
        """
        pass

    @abstractmethod
    def collect_artifacts(self, environment_id: str) -> List[SandboxArtifact]:
        """
        Collects runtime telemetry artifacts generated during analysis.
        Returns list of SandboxArtifact objects.
        """
        pass

    @abstractmethod
    def stop_analysis(self, environment_id: str) -> bool:
        """
        Stops analysis process inside environment boundary.
        """
        pass

    @abstractmethod
    def destroy_environment(self, environment_id: str) -> bool:
        """
        Reverts snapshot or completely destroys guest VM / environment instance.
        """
        pass

    @abstractmethod
    def get_status(self, environment_id: str) -> SandboxJobStatus:
        """
        Queries status of specified environment instance.
        """
        pass
