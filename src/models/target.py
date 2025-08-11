"""Target model for representing scan targets."""

from dataclasses import dataclass
from typing import List, Optional

@dataclass(frozen=True) # Use frozen to make it hashable for use in sets
class Target:
    """Represents a scan target with IP and optional ports."""
    
    ip_address: str
    ports: Optional[tuple] = None # Use tuple to make it hashable
    hostname: Optional[str] = None
    
    @property
    def has_specific_ports(self) -> bool:
        """Check if target has specific ports defined."""
        return self.ports is not None and len(self.ports) > 0
    
    def __str__(self):
        if self.has_specific_ports and self.ports is not None:
            return f"{self.ip_address}:{','.join(map(str, sorted(self.ports)))}"
        return self.ip_address