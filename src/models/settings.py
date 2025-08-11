"""Settings model for application configuration."""

from dataclasses import dataclass, asdict, fields
from typing import Dict, Any, List
import json

@dataclass
class ScanSettings:
    """Holds all configurable application settings."""

    # General Scan Settings
    enable_service_detection: bool = True
    enable_script_scan: bool = True
    enable_os_detection: bool = False
    enable_aggressive_scan: bool = False
    default_scan_type: str = "1000"
    verbose_output: bool = False
    save_xml: bool = True

    # Performance
    timeout: int = 600
    enable_rate_limit: bool = False
    rate_limit_value: int = 100
    scan_delay: float = 0.0
    timing_template: int = 4  # Nmap's -T4 (Aggressive)

    # Security Analysis
    enable_tls_analysis: bool = True
    enable_ssl_analysis: bool = True
    enable_smb_analysis: bool = True
    enable_web_detection: bool = True

    # GUI Settings
    show_tooltips: bool = True
    confirm_actions: bool = True
    remember_window: bool = True
    window_width: int = 1400
    window_height: int = 900
    
    # Advanced / Internal
    nmap_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert settings to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanSettings':
        """Create settings from a dictionary, ignoring unknown keys."""
        known_fields = {f.name for f in fields(cls)}
        filtered_data = {k: v for k, v in data.items() if k in known_fields}
        return cls(**filtered_data)

    def save_to_file(self, filepath: str):
        """Save settings to JSON file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=4)
    
    @classmethod
    def load_from_file(cls, filepath: str) -> 'ScanSettings':
        """Load settings from JSON file."""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls.from_dict(data)