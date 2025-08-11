"""Configuration management for ReMap."""

import json
from pathlib import Path

from ..models.settings import ScanSettings
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ConfigManager:
    """Manages application configuration, including loading and saving settings."""
    
    def __init__(self):
        self.config_dir = Path.home() / ".remap"
        self.settings_file = self.config_dir / "settings.json"
        self.scans_dir = self.config_dir / "scans"
        self.reports_dir = self.config_dir / "reports"
        self.logs_dir = self.config_dir / "logs"
        self._ensure_directories()
        
    def _ensure_directories(self):
        """Create configuration directories if they don't exist."""
        try:
            for d in [self.config_dir, self.scans_dir, self.reports_dir, self.logs_dir]:
                d.mkdir(exist_ok=True, parents=True)
        except OSError as e:
            # Handle potential permissions errors
            logger.error(f"Could not create necessary directory {d}: {e}")
    
    def load_settings(self) -> ScanSettings:
        """Load settings from the JSON file or return default settings if not found/invalid."""
        if self.settings_file.exists():
            try:
                return ScanSettings.load_from_file(str(self.settings_file))
            except (json.JSONDecodeError, TypeError, KeyError) as e:
                logger.warning(f"Error loading settings file at {self.settings_file}: {e}. Using defaults.")
            except Exception as e:
                 logger.error(f"Unexpected error loading settings: {e}", exc_info=True)
        
        logger.info("No valid settings file found, using default settings.")
        return ScanSettings() # Return defaults
    
    def save_settings(self, settings: ScanSettings):
        """Save settings to the JSON file."""
        try:
            settings.save_to_file(str(self.settings_file))
            logger.info(f"Settings successfully saved to {self.settings_file}")
        except Exception as e:
            logger.error(f"Error saving settings to {self.settings_file}: {e}", exc_info=True)