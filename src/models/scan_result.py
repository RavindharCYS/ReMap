"""Scan result models."""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from datetime import datetime

@dataclass
class Port:
    """Represents a scanned port."""
    number: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    extra_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Host:
    """Represents a scanned host."""
    ip_address: str
    hostname: Optional[str] = None
    state: str = "unknown"
    ports: List[Port] = field(default_factory=list)
    os_info: Optional[str] = None
    extra_info: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanResult:
    """Complete scan results."""
    hosts: List[Host] = field(default_factory=list)
    scan_info: Dict[str, Any] = field(default_factory=dict)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_hosts: int = 0
    hosts_up: int = 0
    
    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary dictionary of the scan results."""
        if not self.hosts:
            return {}
            
        open_ports = sum(1 for host in self.hosts for port in host.ports if port.state == 'open')
        
        return {
            'total_hosts': self.total_hosts,
            'hosts_up': self.hosts_up,
            'scan_time': self.start_time,
            'duration': self.duration or 0.0,
            'open_ports': open_ports,
        }