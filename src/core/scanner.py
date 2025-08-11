"""Main scanning logic coordinator."""

import os
import threading
import time
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
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Scanner:
    """Main scanner class that coordinates all scanning operations."""
    
    def __init__(self, settings: ScanSettings):
        self.settings = settings
        self.nmap_wrapper = NmapWrapper(settings)
        self.rate_limiter = RateLimiter(settings.rate_limit_value if settings.enable_rate_limit else 0)
        
        self.status = ScanStatus.IDLE
        self.current_scan_thread = None
        self.cancel_event = threading.Event()
        self.progress_callback = None
        self.completion_callback = None
        
        # Scan results
        self.current_result = None
        self.scan_history = []
        
    def set_progress_callback(self, callback: Callable[[str], None]):
        """Set callback for progress updates."""
        self.progress_callback = callback
    
    def set_completion_callback(self, callback: Callable[[ScanResult, bool], None]):
        """Set callback for scan completion."""
        self.completion_callback = callback
    
    def update_settings(self, settings: ScanSettings):
        """Update scanner settings."""
        self.settings = settings
        self.nmap_wrapper = NmapWrapper(settings)
        self.rate_limiter.set_rate(settings.rate_limit_value if settings.enable_rate_limit else 0)
    
    def start_scan(self, targets: List[Target], scan_type: str = "fast") -> bool:
        """Start a new scan in a separate thread."""
        if self.status == ScanStatus.RUNNING:
            logger.warning("Scan already running")
            return False
        
        if not targets:
            logger.error("No targets provided for scan")
            return False
        
        # Validate targets
        issues = TargetParser.validate_targets(targets)
        error_issues = [issue for issue in issues if not issue.startswith("Warning:")]
        if error_issues:
            logger.error(f"Target validation failed: {'; '.join(error_issues)}")
            return False
        
        # Reset cancel event
        self.cancel_event.clear()
        
        # Start scan thread
        self.current_scan_thread = threading.Thread(
            target=self._run_scan,
            args=(targets, scan_type),
            daemon=True
        )
        self.current_scan_thread.start()
        
        logger.info(f"Started scan thread for {len(targets)} targets")
        return True
    
    def cancel_scan(self):
        """Cancel the current scan."""
        if self.status == ScanStatus.RUNNING:
            logger.info("Cancelling scan...")
            self.cancel_event.set()
    
    def _run_scan(self, targets: List[Target], scan_type: str):
        """Run scan in separate thread."""
        try:
            self.status = ScanStatus.RUNNING
            self._send_progress("Starting scan...")
            
            # Check if Nmap is available
            if not self.nmap_wrapper.test_nmap():
                raise Exception("Nmap is not available or not working correctly")
            
            # Handle targets with specific ports separately
            scan_groups = self._group_targets_for_scanning(targets)
            all_results = []
            
            for group_idx, (target_list, port_spec) in enumerate(scan_groups):
                if self.cancel_event.is_set():
                    self.status = ScanStatus.CANCELLED
                    self._send_progress("Scan cancelled")
                    return
                
                self._send_progress(f"Scanning group {group_idx + 1}/{len(scan_groups)}: {len(target_list)} targets")
                
                # Apply rate limiting
                if group_idx > 0:
                    self.rate_limiter.acquire()
                
                # Execute scan for this group
                result = self._execute_single_scan(target_list, scan_type, port_spec)
                
                if result:
                    all_results.append(result)
                else:
                    logger.warning(f"Scan group {group_idx + 1} failed")
            
            if self.cancel_event.is_set():
                self.status = ScanStatus.CANCELLED
                self._send_progress("Scan cancelled")
                return
            
            # Merge results
            if all_results:
                self.current_result = self._merge_scan_results(all_results)
                self.status = ScanStatus.COMPLETED
                self._send_progress(f"Scan completed: {self.current_result.hosts_up}/{self.current_result.total_hosts} hosts up")
                
                # Add to history
                self.scan_history.append({
                    'timestamp': datetime.now(),
                    'targets_count': len(targets),
                    'scan_type': scan_type,
                    'hosts_found': self.current_result.hosts_up,
                    'duration': self.current_result.duration
                })
                
                # Call completion callback
                if self.completion_callback:
                    self.completion_callback(self.current_result, True)
            else:
                self.status = ScanStatus.FAILED
                self._send_progress("Scan failed: No results obtained")
                if self.completion_callback:
                    self.completion_callback(None, False)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.status = ScanStatus.FAILED
            self._send_progress(f"Scan failed: {str(e)}")
            if self.completion_callback:
                self.completion_callback(None, False)
    
    def _group_targets_for_scanning(self, targets: List[Target]) -> List[tuple]:
        """Group targets for efficient scanning."""
        groups = []
        
        # Separate targets without specific ports
        regular_targets = [t for t in targets if not t.has_specific_ports]
        if regular_targets:
            target_ips = [t.ip_address for t in regular_targets]
            groups.append((target_ips, None))
        
        # Group targets with same port specifications
        port_groups = {}
        for target in targets:
            if target.has_specific_ports:
                port_key = tuple(sorted(target.ports))
                if port_key not in port_groups:
                    port_groups[port_key] = []
                port_groups[port_key].append(target.ip_address)
        
        for ports, ips in port_groups.items():
            groups.append((ips, list(ports)))
        
        return groups
    
    def _execute_single_scan(self, target_ips: List[str], scan_type: str, 
                           specific_ports: Optional[List[int]] = None) -> Optional[ScanResult]:
        """Execute a single Nmap scan."""
        try:
            # Modify scan type if specific ports are provided
            effective_scan_type = scan_type
            if specific_ports:
                # Override scan type for specific ports
                effective_scan_type = "custom"
            
            # Execute Nmap scan
            nmap_result = self.nmap_wrapper.execute_scan(
                target_ips, 
                effective_scan_type,
                progress_callback=self._send_progress
            )
            
            if nmap_result['return_code'] != 0:
                logger.error(f"Nmap scan failed: {' '.join(nmap_result['stderr'])}")
                return None
            
            xml_file = nmap_result['xml_file']
            if not xml_file or not os.path.exists(xml_file):
                logger.error("No XML output file generated")
                return None
            
            # Parse XML results
            scan_result = NmapXMLParser.parse_xml_file(xml_file)
            
            # Clean up temporary XML file if configured
            if not self.settings.save_xml:
                try:
                    os.unlink(xml_file)
                except OSError:
                    pass
            else:
                # Move to permanent location
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                permanent_path = Path.home() / ".remap" / "scans" / f"scan_{timestamp}.xml"
                permanent_path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.rename(xml_file, str(permanent_path))
                    logger.info(f"Scan results saved to: {permanent_path}")
                except OSError as e:
                    logger.warning(f"Could not move XML file: {e}")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error executing scan: {e}")
            return None
    
    def _merge_scan_results(self, results: List[ScanResult]) -> ScanResult:
        """Merge multiple scan results into one."""
        if len(results) == 1:
            return results[0]
        
        merged = ScanResult()
        
        # Merge hosts
        all_hosts = {}
        for result in results:
            for host in result.hosts:
                if host.ip_address in all_hosts:
                    # Merge ports
                    existing_ports = {p.number: p for p in all_hosts[host.ip_address].ports}
                    for port in host.ports:
                        if port.number not in existing_ports:
                            all_hosts[host.ip_address].ports.append(port)
                else:
                    all_hosts[host.ip_address] = host
        
        merged.hosts = list(all_hosts.values())
        merged.total_hosts = len(merged.hosts)
        merged.hosts_up = len([h for h in merged.hosts if h.state == 'up'])
        
        # Use timing from first result
        if results:
            merged.start_time = results[0].start_time
            merged.end_time = max((r.end_time for r in results if r.end_time), default=None)
        
        # Merge scan info
        merged.scan_info = {}
        for result in results:
            merged.scan_info.update(result.scan_info)
        
        return merged
    
    def _send_progress(self, message: str):
        """Send progress update to callback."""
        logger.info(message)
        if self.progress_callback:
            try:
                self.progress_callback(message)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
    
    def load_xml_results(self, xml_file_path: str) -> bool:
        """Load scan results from existing XML file."""
        try:
            if not NmapXMLParser.validate_xml_file(xml_file_path):
                logger.error(f"Invalid XML file: {xml_file_path}")
                return False
            
            self.current_result = NmapXMLParser.parse_xml_file(xml_file_path)
            self.status = ScanStatus.COMPLETED
            
            logger.info(f"Loaded scan results from: {xml_file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading XML file: {e}")
            return False
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of current scan results."""
        if not self.current_result:
            return {}
        
        # Count services
        service_counts = {}
        open_ports = 0
        
        for host in self.current_result.hosts:
            for port in host.ports:
                if port.state == 'open':
                    open_ports += 1
                    service = port.service or 'unknown'
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        return {
            'total_hosts': self.current_result.total_hosts,
            'hosts_up': self.current_result.hosts_up,
            'open_ports': open_ports,
            'top_services': sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10],
            'duration': self.current_result.duration,
            'scan_time': self.current_result.start_time
        }
    
    def is_scanning(self) -> bool:
        """Check if scan is currently running."""
        return self.status == ScanStatus.RUNNING
    
    def get_status(self) -> str:
        """Get current scan status."""
        return self.status