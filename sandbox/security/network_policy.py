from typing import List
from pydantic import BaseModel, Field


class NetworkPolicy(BaseModel):
    """
    Declarative network containment policy for isolated dynamic analysis environments.
    Default configuration MUST be internet_access = False and network_mode = 'isolated'.
    """
    internet_access: bool = Field(False, description="Default internet access flag (MUST default to False)")
    network_mode: str = Field("isolated", description="Network mode: 'isolated', 'sinkhole', or 'proxy'")
    allowed_destinations: List[str] = Field(default_factory=list, description="Explicit whitelist of allowed IP/domain destinations")
    blocked_destinations: List[str] = Field(default_factory=lambda: ["*"], description="Default blocklist (all destinations blocked by default)")
    dns_policy: str = Field("sinkhole", description="DNS resolution policy: 'sinkhole', 'drop', or 'simulated'")
    inbound_policy: str = Field("deny_all", description="Inbound firewall policy")
    outbound_policy: str = Field("deny_all", description="Outbound firewall policy")
    max_outbound_bytes: int = Field(10 * 1024 * 1024, ge=0, description="Maximum outbound network byte cap (10MB default)")

    def validate_policy(self) -> bool:
        """Validates network containment rules."""
        if self.internet_access and self.network_mode == "isolated":
            raise ValueError("Invalid NetworkPolicy: internet_access cannot be True when network_mode is 'isolated'.")
        return True
