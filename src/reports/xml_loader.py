"""XML loader for existing Nmap reports."""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime

from ..core.xml_parser import NmapXMLParser
from ..models.scan_result import ScanResult
from ..utils.logger import setup_logger
from ..utils.validators import Validators

logger = setup_logger(__name__)

class XMLLoader:
    """Load and manage existing XML scan reports."""
    
    def __init__(self):
        self.loaded_reports = {}  # Cache for loaded reports
    
    def load_xml_report(self, xml_file_path: str) -> Optional[ScanResult]:
        """
        Load Nmap XML report.
        
        Args:
            xml_file_path: Path to XML file
            
        Returns:
            ScanResult object or None if loading failed
        """
        try:
            if not Validators.validate_xml_file(xml_file_path):
                raise ValueError(f"Invalid XML file: {xml_file_path}")
            
            # Check if already loaded
            file_path = Path(xml_file_path).resolve()
            if str(file_path) in self.loaded_reports:
                logger.info(f"Using cached XML report: {xml_file_path}")
                return self.loaded_reports[str(file_path)]
            
            # Parse XML file
            scan_result = NmapXMLParser.parse_xml_file(xml_file_path)
            
            # Cache the result
            self.loaded_reports[str(file_path)] = scan_result
            
            logger.info(f"Loaded XML report: {xml_file_path}")
            logger.info(f"Report contains {scan_result.total_hosts} hosts, {scan_result.hosts_up} up")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to load XML report {xml_file_path}: {e}")
            return None
    
    def load_multiple_xml_reports(self, xml_file_paths: List[str]) -> List[ScanResult]:
        """
        Load multiple XML reports.
        
        Args:
            xml_file_paths: List of XML file paths
            
        Returns:
            List of successfully loaded ScanResult objects
        """
        results = []
        
        for xml_path in xml_file_paths:
            try:
                scan_result = self.load_xml_report(xml_path)
                if scan_result:
                    results.append(scan_result)
            except Exception as e:
                logger.error(f"Failed to load XML report {xml_path}: {e}")
                continue
        
        logger.info(f"Loaded {len(results)} out of {len(xml_file_paths)} XML reports")
        return results
    
    def merge_xml_reports(self, xml_file_paths: List[str]) -> Optional[ScanResult]:
        """
        Load and merge multiple XML reports into a single ScanResult.
        
        Args:
            xml_file_paths: List of XML file paths to merge
            
        Returns:
            Merged ScanResult or None if no reports could be loaded
        """
        try:
            scan_results = self.load_multiple_xml_reports(xml_file_paths)
            
            if not scan_results:
                logger.warning("No XML reports could be loaded for merging")
                return None
            
            if len(scan_results) == 1:
                return scan_results[0]
            
            # Merge the results
            merged_result = ScanResult()
            all_hosts = {}
            
            # Combine scan info from first result
            merged_result.scan_info = scan_results[0].scan_info.copy()
            merged_result.start_time = min((r.start_time for r in scan_results if r.start_time), 
                                         default=None)
            merged_result.end_time = max((r.end_time for r in scan_results if r.end_time), 
                                       default=None)
            
            # Merge hosts
            for scan_result in scan_results:
                for host in scan_result.hosts:
                    host_key = host.ip_address
                    
                    if host_key in all_hosts:
                        # Merge ports from existing host
                        existing_host = all_hosts[host_key]
                        existing_ports = {p.number: p for p in existing_host.ports}
                        
                        for port in host.ports:
                            if port.number not in existing_ports:
                                existing_host.ports.append(port)
                            else:
                                # Update port info if new one has more details
                                existing_port = existing_ports[port.number]
                                if port.service and not existing_port.service:
                                    existing_port.service = port.service
                                if port.version and not existing_port.version:
                                    existing_port.version = port.version
                        
                        # Update host info if new one has more details
                        if host.hostname and not existing_host.hostname:
                            existing_host.hostname = host.hostname
                        if host.os_info and not existing_host.os_info:
                            existing_host.os_info = host.os_info
                        
                        # Merge extra info
                        if host.extra_info:
                            existing_host.extra_info.update(host.extra_info)
                    else:
                        all_hosts[host_key] = host
            
            merged_result.hosts = list(all_hosts.values())
            merged_result.total_hosts = len(merged_result.hosts)
            merged_result.hosts_up = len([h for h in merged_result.hosts if h.state == 'up'])
            
            logger.info(f"Merged {len(scan_results)} XML reports into single result")
            logger.info(f"Merged result: {merged_result.total_hosts} hosts, {merged_result.hosts_up} up")
            
            return merged_result
            
        except Exception as e:
            logger.error(f"Failed to merge XML reports: {e}")
            return None
    
    def get_xml_report_info(self, xml_file_path: str) -> Optional[Dict[str, Any]]:
        """
        Get basic information about an XML report without fully parsing it.
        
        Args:
            xml_file_path: Path to XML file
            
        Returns:
            Dictionary with report information or None if failed
        """
        try:
            if not Validators.validate_xml_file(xml_file_path):
                return None
            
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            # Basic info
            info = {
                'file_path': xml_file_path,
                'file_size': Path(xml_file_path).stat().st_size,
                'scanner': root.attrib.get('scanner', 'Unknown'),
                'version': root.attrib.get('version', 'Unknown'),
                'start_time': None,
                'total_hosts': 0,
                'hosts_up': 0
            }
            
            # Parse start time
            if 'start' in root.attrib:
                try:
                    info['start_time'] = datetime.fromtimestamp(int(root.attrib['start']))
                except (ValueError, TypeError):
                    pass
                      
            # Count hosts that are up
            hosts_up = 0
            for host in hosts:
                status = host.find('status')
                if status is not None and status.attrib.get('state') == 'up':
                    hosts_up += 1
            
            info['hosts_up'] = hosts_up
            
            # Get scan info
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                info['scan_type'] = scaninfo.attrib.get('type', 'Unknown')
                info['protocol'] = scaninfo.attrib.get('protocol', 'Unknown')
                info['services'] = scaninfo.attrib.get('services', 'Unknown')
            
            # Get run stats
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    if 'time' in finished.attrib:
                        try:
                            end_time = datetime.fromtimestamp(int(finished.attrib['time']))
                            if info['start_time']:
                                info['duration'] = (end_time - info['start_time']).total_seconds()
                            info['end_time'] = end_time
                        except (ValueError, TypeError):
                            pass
                    
                    info['elapsed'] = finished.attrib.get('elapsed', 'Unknown')
                    info['exit'] = finished.attrib.get('exit', 'Unknown')
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get XML report info for {xml_file_path}: {e}")
            return None
    
    def list_recent_xml_reports(self, scan_directory: Optional[str] = None, 
                               limit: int = 10) -> List[Dict[str, Any]]:
        """
        List recent XML reports from scan directory.
        
        Args:
            scan_directory: Directory to search (default: ~/.remap/scans)
            limit: Maximum number of reports to return
            
        Returns:
            List of report information dictionaries
        """
        try:
            if scan_directory is None:
                scan_directory = str(Path.home() / ".remap" / "scans")
            
            scan_dir = Path(scan_directory)
            if not scan_dir.exists():
                logger.warning(f"Scan directory does not exist: {scan_directory}")
                return []
            
            # Find XML files
            xml_files = list(scan_dir.glob("*.xml"))
            
            if not xml_files:
                logger.info(f"No XML files found in {scan_directory}")
                return []
            
            # Sort by modification time (newest first)
            xml_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            
            # Get info for each file
            reports_info = []
            for xml_file in xml_files[:limit]:
                info = self.get_xml_report_info(str(xml_file))
                if info:
                    info['file_modified'] = datetime.fromtimestamp(xml_file.stat().st_mtime)
                    reports_info.append(info)
            
            logger.info(f"Found {len(reports_info)} recent XML reports")
            return reports_info
            
        except Exception as e:
            logger.error(f"Failed to list recent XML reports: {e}")
            return []
    
    def validate_xml_integrity(self, xml_file_path: str) -> Dict[str, Any]:
        """
        Validate XML file integrity and structure.
        
        Args:
            xml_file_path: Path to XML file
            
        Returns:
            Dictionary with validation results
        """
        validation_result = {
            'is_valid': False,
            'is_nmap_xml': False,
            'has_hosts': False,
            'has_ports': False,
            'errors': [],
            'warnings': []
        }
        
        try:
            # Check if file exists and is readable
            if not Path(xml_file_path).exists():
                validation_result['errors'].append("File does not exist")
                return validation_result
            
            if not Path(xml_file_path).is_file():
                validation_result['errors'].append("Path is not a file")
                return validation_result
            
            # Try to parse XML
            try:
                tree = ET.parse(xml_file_path)
                root = tree.getroot()
                validation_result['is_valid'] = True
            except ET.ParseError as e:
                validation_result['errors'].append(f"XML parsing error: {e}")
                return validation_result
            
            # Check if it's Nmap XML
            if root.tag != 'nmaprun':
                validation_result['errors'].append("Not an Nmap XML file (missing nmaprun root)")
                return validation_result
            
            validation_result['is_nmap_xml'] = True
            
            # Check required attributes
            required_attrs = ['scanner', 'start']
            for attr in required_attrs:
                if attr not in root.attrib:
                    validation_result['warnings'].append(f"Missing required attribute: {attr}")
            
            # Check for hosts
            hosts = root.findall('host')
            if hosts:
                validation_result['has_hosts'] = True
                
                # Check for ports
                for host in hosts[:5]:  # Check first 5 hosts
                    ports = host.find('ports')
                    if ports is not None and ports.findall('port'):
                        validation_result['has_ports'] = True
                        break
                
                if not validation_result['has_ports']:
                    validation_result['warnings'].append("No open ports found in scan")
            else:
                validation_result['warnings'].append("No hosts found in scan")
            
            # Check scan completion
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None:
                    exit_code = finished.attrib.get('exit')
                    if exit_code != 'success':
                        validation_result['warnings'].append(f"Scan exit status: {exit_code}")
            else:
                validation_result['warnings'].append("No run statistics found (scan may be incomplete)")
            
            logger.debug(f"XML validation completed for {xml_file_path}")
            return validation_result
            
        except Exception as e:
            validation_result['errors'].append(f"Validation error: {str(e)}")
            logger.error(f"XML validation failed for {xml_file_path}: {e}")
            return validation_result
    
    def extract_scan_targets(self, xml_file_path: str) -> List[str]:
        """
        Extract original scan targets from XML file.
        
        Args:
            xml_file_path: Path to XML file
            
        Returns:
            List of target IP addresses/ranges that were scanned
        """
        targets = []
        
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            # Look for target specification in scan info
            scaninfo = root.find('scaninfo')
            if scaninfo is not None:
                services = scaninfo.attrib.get('services', '')
                if services:
                    logger.debug(f"Scanned services: {services}")
            
            # Extract targets from hosts
            hosts = root.findall('host')
            for host in hosts:
                # Get IP address
                address = host.find('address[@addrtype="ipv4"]')
                if address is None:
                    address = host.find('address[@addrtype="ipv6"]')
                
                if address is not None:
                    ip_addr = address.attrib['addr']
                    if ip_addr not in targets:
                        targets.append(ip_addr)
            
            # Look for target specification in command line (if available)
            verbose = root.find('verbose')
            if verbose is not None:
                level = verbose.attrib.get('level', '0')
                logger.debug(f"Scan verbose level: {level}")
            
            logger.info(f"Extracted {len(targets)} targets from XML file")
            return sorted(targets)
            
        except Exception as e:
            logger.error(f"Failed to extract targets from {xml_file_path}: {e}")
            return []
    
    def clear_cache(self):
        """Clear the loaded reports cache."""
        self.loaded_reports.clear()
        logger.debug("XML loader cache cleared")
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get information about cached reports."""
        return {
            'cached_reports': len(self.loaded_reports),
            'cache_files': list(self.loaded_reports.keys())
        }