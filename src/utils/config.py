"""Configuration management."""

import os
import json
from pathlib import Path
from typing import Dict, Any
from models.settings import ScanSettings

class ConfigManager:
    """Manages application configuration."""
    
    def __init__(self):
        self.config_dir = Path.home() / ".remap"
        self.config_file = self.config_dir / "settings.json"
        self.ensure_config_directory()
        
    def ensure_config_directory(self):
        """Create configuration directory if it doesn't exist."""
        self.config_dir.mkdir(exist_ok=True)
    
    def load_settings(self) -> ScanSettings:
        """Load settings from file or return defaults."""
        if self.config_file.exists():
            try:
                return ScanSettings.load_from_file(str(self.config_file))
            except Exception as e:
                print(f"Error loading settings: {e}")
        
        return ScanSettings()  # Return defaults
    
    def save_settings(self, settings: ScanSettings):
        """Save settings to file."""
        try:
            settings.save_to_file(str(self.config_file))
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def get_default_settings_path(self) -> str:
        """Get path to default settings file."""
        return os.path.join(os.path.dirname(__file__), "..", "..", "resources", "config", "default_settings.json")