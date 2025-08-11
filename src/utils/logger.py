"""Logging configuration."""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler

def setup_logger(name: str = "ReMap") -> logging.Logger:
    """Set up a logger with console and rotating file handlers."""
    
    log_dir = Path.home() / ".remap" / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        # Fallback to console logging if file system is not writable
        print(f"Warning: Could not create log directory {log_dir}: {e}")
        # Return a basic logger
        logger = logging.getLogger(name)
        if not logger.handlers:
             handler = logging.StreamHandler(sys.stdout)
             formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
             handler.setFormatter(formatter)
             logger.addHandler(handler)
             logger.setLevel(logging.INFO)
        return logger

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger # Avoid adding duplicate handlers

    logger.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
    console_handler.setFormatter(console_formatter)
    
    # File handler (rotating)
    log_file = log_dir / "remap.log"
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s')
    file_handler.setFormatter(file_formatter)
    
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger