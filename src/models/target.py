"""Target model for representing scan targets."""

from dataclasses import dataclass
from typing import List, Optional
import ipaddress

@dataclass
class Target:
    """Represents a scan target with IP and optional ports."""
    
    ip_address: str
    ports: Optional[List[int]] = None
    hostname: Optional[str] = None
    
    def __post_init__(self):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError:
            raise ValueError(f"Invalid IP address: {self.ip_address}")
    
    @property
    def has_specific_ports(self) -> bool:
        """Check if target has specific ports defined."""
        return self.ports is not None and len(self.ports) > 0
    
    def __str__(self):
        if self.has_specific_ports:
            return f"{self.ip_address}:{','.join(map(str, self.ports))}"
        return self.ip_address