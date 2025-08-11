"""Settings model for application configuration."""

from dataclasses import dataclass, asdict
from typing import Dict, Any
import json

@dataclass
class ScanSettings:
    """Application settings configuration."""
    
    # Rate limiting
    enable_rate_limit: bool = False
    rate_limit_value: int = 100
    
    # Scan options
    enable_service_detection: bool = True
    enable_version_detection: bool = True
    enable_os_detection: bool = False
    enable_script_scan: bool = False
    
    # Advanced options
    timeout: int = 300
    max_retries: int = 3
    scan_delay: float = 0.0
    
    # Output options
    verbose_output: bool = False
    save_xml: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanSettings':
        """Create settings from dictionary."""
        return cls(**data)
    
    def save_to_file(self, filepath: str):
        """Save settings to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'ScanSettings':
        """Load settings from JSON file."""
        with open(filepath, 'r') as f:
            data = json.load(f)
        return cls.from_dict(data)