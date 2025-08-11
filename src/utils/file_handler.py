"""File operations utilities."""

import os
import shutil
from pathlib import Path
from typing import Optional
import json

from .logger import setup_logger

logger = setup_logger(__name__)

class FileHandler:
    """Utility class for common file operations."""
    
    @staticmethod
    def ensure_directory_exists(directory_path: str):
        """Ensure a directory exists, creating it if necessary."""
        try:
            Path(directory_path).mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error(f"Failed to create directory {directory_path}: {e}")
            raise

    @staticmethod
    def read_text_file(file_path: str) -> Optional[str]:
        """Read a text file, attempting multiple encodings."""
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252']
        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    return f.read()
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")
                return None
        logger.error(f"Could not decode file {file_path} with any attempted encoding.")
        return None

    @staticmethod
    def write_text_file(file_path: str, content: str) -> bool:
        """Write text to a file, ensuring the directory exists."""
        try:
            FileHandler.ensure_directory_exists(os.path.dirname(file_path))
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Error writing to file {file_path}: {e}")
            return False

    @staticmethod
    def read_json_file(file_path: str) -> Optional[dict]:
        """Read and parse a JSON file."""
        content = FileHandler.read_text_file(file_path)
        if content is None: return None
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path}: {e}")
            return None

    @staticmethod
    def write_json_file(file_path: str, data: dict) -> bool:
        """Write dictionary to a JSON file."""
        try:
            content = json.dumps(data, indent=4, default=str)
            return FileHandler.write_text_file(file_path, content)
        except Exception as e:
            logger.error(f"Error serializing data for JSON file {file_path}: {e}")
            return False