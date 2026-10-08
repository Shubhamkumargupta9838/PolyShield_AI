from pydantic import BaseModel, Field


class IsolationPolicy(BaseModel):
    """
    Declarative security isolation policy enforcing non-negotiable trust boundary controls
    between host environment and sandbox execution environment.
    """
    deny_host_filesystem: bool = Field(True, description="Strictly deny mounting host filesystem or user home directories")
    deny_host_processes: bool = Field(True, description="Strictly deny guest access to host process space or IPC")
    deny_docker_socket: bool = Field(True, description="Strictly deny exposing Docker socket /var/run/docker.sock to guest")
    deny_shared_folders: bool = Field(True, description="Strictly deny shared host-guest folders")
    deny_shared_clipboard: bool = Field(True, description="Strictly deny shared clipboard (copy/paste passthrough)")
    deny_usb_passthrough: bool = Field(True, description="Strictly deny host USB device passthrough")
    deny_secret_access: bool = Field(True, description="Strictly deny guest access to .env, API keys, SSH keys, or DB credentials")

    def validate_policy(self) -> bool:
        """Enforces that all security isolation rules are non-negotiable True."""
        if not (
            self.deny_host_filesystem
            and self.deny_host_processes
            and self.deny_docker_socket
            and self.deny_shared_folders
            and self.deny_shared_clipboard
            and self.deny_usb_passthrough
            and self.deny_secret_access
        ):
            raise ValueError("Invalid IsolationPolicy: All host isolation flags MUST be True.")
        return True
