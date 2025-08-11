"""File operations utilities."""

import os
import shutil
from pathlib import Path
from typing import List, Optional
import tempfile
import json
from datetime import datetime

from .logger import setup_logger

logger = setup_logger(__name__)

class FileHandler:
    """Utility class for file operations."""
    
    @staticmethod
    def ensure_directory_exists(directory_path: str) -> bool:
        """Ensure directory exists, create if necessary."""
        try:
            Path(directory_path).mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            logger.error(f"Failed to create directory {directory_path}: {e}")
            return False
    
    @staticmethod
    def read_text_file(file_path: str, encoding: str = 'utf-8') -> Optional[str]:
        """Read text file with error handling."""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except UnicodeDecodeError:
            # Try alternative encodings
            for alt_encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
                try:
                    with open(file_path, 'r', encoding=alt_encoding) as f:
                        logger.info(f"Read file with {alt_encoding} encoding: {file_path}")
                        return f.read()
                except UnicodeDecodeError:
                    continue
            
            logger.error(f"Could not read file with any encoding: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return None
    
    @staticmethod
    def write_text_file(file_path: str, content: str, encoding: str = 'utf-8') -> bool:
        """Write text file with error handling."""
        try:
            # Ensure directory exists
            FileHandler.ensure_directory_exists(os.path.dirname(file_path))
            
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            return True
        except Exception as e:
            logger.error(f"Error writing file {file_path}: {e}")
            return False
    
    @staticmethod
    def read_json_file(file_path: str) -> Optional[dict]:
        """Read JSON file with error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in file {file_path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error reading JSON file {file_path}: {e}")
            return None
    
    @staticmethod
    def write_json_file(file_path: str, data: dict, indent: int = 2) -> bool:
        """Write JSON file with error handling."""
        try:
            # Ensure directory exists
            FileHandler.ensure_directory_exists(os.path.dirname(file_path))
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, ensure_ascii=False, default=str)
            return True
        except Exception as e:
            logger.error(f"Error writing JSON file {file_path}: {e}")
            return False
    
    @staticmethod
    def copy_file(source_path: str, destination_path: str) -> bool:
        """Copy file with error handling."""
        try:
            # Ensure destination directory exists
            FileHandler.ensure_directory_exists(os.path.dirname(destination_path))
            
            shutil.copy2(source_path, destination_path)
            return True
        except Exception as e:
            logger.error(f"Error copying file from {source_path} to {destination_path}: {e}")
            return False
    
    @staticmethod
    def move_file(source_path: str, destination_path: str) -> bool:
        """Move file with error handling."""
        try:
            # Ensure destination directory exists
            FileHandler.ensure_directory_exists(os.path.dirname(destination_path))
            
            shutil.move(source_path, destination_path)
            return True
        except Exception as e:
            logger.error(f"Error moving file from {source_path} to {destination_path}: {e}")
            return False
    
    @staticmethod
    def delete_file(file_path: str) -> bool:
        """Delete file with error handling."""
        try:
            os.remove(file_path)
            return True
        except FileNotFoundError:
            return True  # File already doesn't exist
        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
            return False
    
    @staticmethod
    def get_file_size(file_path: str) -> Optional[int]:
        """Get file size in bytes."""
        try:
            return os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"Error getting size of file {file_path}: {e}")
            return None
    
    @staticmethod
    def file_exists(file_path: str) -> bool:
        """Check if file exists."""
        return os.path.isfile(file_path)
    
    @staticmethod
    def create_backup_filename(original_path: str) -> str:
        """Create backup filename with timestamp."""
        path = Path(original_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return str(path.with_name(f"{path.stem}_backup_{timestamp}{path.suffix}"))
    
    @staticmethod
    def create_temp_file(suffix: str = '', prefix: str = 'remap_') -> str:
        """Create temporary file and return path."""
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
        os.close(fd)  # Close the file descriptor
        return path
    
    @staticmethod
    def cleanup_temp_files(temp_files: List[str]):
        """Clean up temporary files."""
        for temp_file in temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
                    logger.debug(f"Cleaned up temp file: {temp_file}")
            except Exception as e:
                logger.warning(f"Failed to clean up temp file {temp_file}: {e}")
    
    @staticmethod
    def get_safe_filename(filename: str) -> str:
        """Convert filename to safe format by removing/replacing invalid characters."""
        # Characters to remove or replace
        invalid_chars = '<>:"/\\|?*'
        safe_filename = filename
        
        for char in invalid_chars:
            safe_filename = safe_filename.replace(char, '_')
        
        # Remove any trailing periods or spaces
        safe_filename = safe_filename.rstrip('. ')
        
        # Ensure filename is not empty
        if not safe_filename:
            safe_filename = "unnamed"
        
        # Truncate if too long (Windows has 255 char limit)
        if len(safe_filename) > 200:
            name, ext = os.path.splitext(safe_filename)
            safe_filename = name[:200-len(ext)] + ext
        
        return safe_filename