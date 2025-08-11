"""Data models for scan results and configuration."""
from .target import Target
from .scan_result import ScanResult, Host, Port
from .settings import ScanSettings

__all__ = ['Target', 'ScanResult', 'Host', 'Port', 'ScanSettings']