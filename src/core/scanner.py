"""Main scanning logic coordinator."""

import os
import threading
import tempfile
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from pathlib import Path

from .nmap_wrapper import NmapWrapper
from .target_parser import TargetParser
from .xml_parser import NmapXMLParser
from .rate_limiter import RateLimiter
from ..models.target import Target
from ..models.scan_result import ScanResult
from ..models.settings import ScanSettings
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class ScanStatus:
    """Scan status enumeration."""
    IDLE = "Idle"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"

class Scanner:
    """Main scanner class that coordinates all scanning operations."""
    
    def __init__(self, settings: ScanSettings):
        self.nmap_wrapper = NmapWrapper(settings)
        self.rate_limiter = RateLimiter(settings.rate_limit_value if settings.enable_rate_limit else 0)
        self.settings = settings

        self.status = ScanStatus.IDLE
        self.current_scan_thread: Optional[threading.Thread] = None
        self.cancel_event = threading.Event()
        self.progress_callback: Optional[Callable[[str], None]] = None
        self.completion_callback: Optional[Callable[[Optional[ScanResult], bool], None]] = None
        
        self.current_result: Optional[ScanResult] = None
        
    def set_progress_callback(self, callback: Optional[Callable[[str], None]]):
        self.progress_callback = callback
    
    def set_completion_callback(self, callback: Optional[Callable[[Optional[ScanResult], bool], None]]):
        self.completion_callback = callback
    
    def update_settings(self, settings: ScanSettings):
        self.settings = settings
        self.nmap_wrapper = NmapWrapper(settings)
        self.rate_limiter.set_rate(settings.rate_limit_value if settings.enable_rate_limit else 0)
    
    def start_scan(self, targets: List[Target], scan_type: str) -> bool:
        if self.status == ScanStatus.RUNNING:
            logger.warning("Scan already running.")
            return False
        
        if not targets:
            logger.error("No targets provided for scan.")
            return False

        self.cancel_event.clear()
        
        self.current_scan_thread = threading.Thread(
            target=self._run_scan_thread,
            args=(targets, scan_type),
            daemon=True
        )
        self.current_scan_thread.start()
        logger.info(f"Started scan thread for {len(targets)} targets.")
        return True
    
    def cancel_scan(self):
        if self.status == ScanStatus.RUNNING:
            logger.info("Cancelling scan...")
            self.cancel_event.set()

    def _run_scan_thread(self, targets: List[Target], scan_type: str):
        self.status = ScanStatus.RUNNING
        self._send_progress("Initializing scan...")

        scan_groups = self._group_targets_for_scanning(targets)
        xml_files = []
        scan_success = True

        for i, (ips, ports) in enumerate(scan_groups):
            if self.cancel_event.is_set():
                self.status = ScanStatus.CANCELLED
                self._send_progress("Scan cancelled by user.")
                break

            self.rate_limiter.acquire()
            self._send_progress(f"Scanning group {i+1}/{len(scan_groups)}...")

            with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp:
                xml_file = tmp.name

            result = self.nmap_wrapper.execute_scan(ips, scan_type, xml_file, ports, self.progress_callback)
            
            if result['return_code'] == 0 and result['xml_file']:
                xml_files.append(result['xml_file'])
            else:
                scan_success = False
                logger.error(f"Scan group {i+1} failed. Stderr: {result['stderr']}")
                self._send_progress(f"Scan group {i+1} failed.")
                try: os.unlink(xml_file)
                except OSError: pass
        
        if self.cancel_event.is_set():
            self._cleanup_temp_files(xml_files)
            if self.completion_callback:
                self.completion_callback(None, False)
            return

        if not scan_success and not xml_files:
            self.status = ScanStatus.FAILED
            self._send_progress("Scan failed. No results generated.")
            if self.completion_callback:
                self.completion_callback(None, False)
            return

        try:
            parser = NmapXMLParser()
            self.current_result = parser.merge_xml_files(xml_files)
            self.status = ScanStatus.COMPLETED
            self._send_progress(f"Scan completed: {self.current_result.hosts_up}/{self.current_result.total_hosts} hosts up.")
            if self.completion_callback:
                self.completion_callback(self.current_result, True)
        except Exception as e:
            logger.error(f"Failed to parse or merge scan results: {e}", exc_info=True)
            self.status = ScanStatus.FAILED
            self._send_progress("Scan failed: Error processing results.")
            if self.completion_callback:
                self.completion_callback(None, False)
        finally:
             self._cleanup_temp_files(xml_files)
    
    def _cleanup_temp_files(self, file_paths: List[str]):
        for f in file_paths:
            try:
                os.unlink(f)
            except OSError as e:
                logger.warning(f"Could not delete temp file {f}: {e}")

    def _group_targets_for_scanning(self, targets: List[Target]) -> List[tuple[List[str], Optional[List[int]]]]:
        groups: Dict[Optional[tuple], List[str]] = {}
        for target in targets:
            key = tuple(sorted(target.ports)) if target.ports else None
            if key not in groups:
                groups[key] = []
            groups[key].append(target.ip_address)
        
        return [(ips, list(ports) if ports else None) for ports, ips in groups.items()]
    
    def _send_progress(self, message: str):
        logger.info(message)
        if self.progress_callback:
            try:
                self.progress_callback(message)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
    
    def is_scanning(self) -> bool:
        return self.status == ScanStatus.RUNNING