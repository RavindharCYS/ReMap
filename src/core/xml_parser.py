"""XML parser for Nmap output."""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models.scan_result import ScanResult, Host, Port
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class NmapXMLParser:
    """Parser for Nmap XML output files."""
    
    @staticmethod
    def parse_xml_file(xml_file_path: str) -> ScanResult:
        """Parse Nmap XML file and return ScanResult object."""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            scan_result = ScanResult()
            scan_result.scan_info = NmapXMLParser._parse_scan_info(root)
            if 'start' in root.attrib:
                scan_result.start_time = datetime.fromtimestamp(int(root.attrib['start']))

            scan_result.hosts = [host for host in (NmapXMLParser._parse_host(h) for h in root.findall('host')) if host]
            scan_result.total_hosts = len(scan_result.hosts)
            scan_result.hosts_up = len([h for h in scan_result.hosts if h.state == 'up'])

            runstats = root.find('runstats/finished')
            if runstats is not None and 'time' in runstats.attrib:
                scan_result.end_time = datetime.fromtimestamp(int(runstats.attrib['time']))
            
            logger.info(f"Parsed XML file: {scan_result.total_hosts} hosts, {scan_result.hosts_up} up.")
            return scan_result
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error in {xml_file_path}: {e}")
            raise ValueError(f"Invalid XML file: {e}")
        except Exception as e:
            logger.error(f"Error parsing XML file {xml_file_path}: {e}", exc_info=True)
            raise
    
    @staticmethod
    def merge_xml_files(xml_files: List[str]) -> ScanResult:
        """Loads and merges multiple XML reports into a single ScanResult."""
        if not xml_files:
            return ScanResult()
        
        if len(xml_files) == 1:
            return NmapXMLParser.parse_xml_file(xml_files[0])
            
        all_results = [NmapXMLParser.parse_xml_file(f) for f in xml_files]
        
        merged_result = ScanResult()
        if all_results:
            merged_result.start_time = min(r.start_time for r in all_results if r.start_time)
            merged_result.end_time = max(r.end_time for r in all_results if r.end_time)
            merged_result.scan_info = all_results[0].scan_info # Use first as base
        
        host_map: Dict[str, Host] = {}
        for result in all_results:
            for host in result.hosts:
                if host.ip_address not in host_map:
                    host_map[host.ip_address] = host
                else: # Merge host data
                    existing_host = host_map[host.ip_address]
                    if not existing_host.hostname and host.hostname:
                        existing_host.hostname = host.hostname
                    if not existing_host.os_info and host.os_info:
                        existing_host.os_info = host.os_info
                    
                    # Merge ports
                    existing_ports = {p.number: p for p in existing_host.ports}
                    for p in host.ports:
                        if p.number not in existing_ports:
                            existing_host.ports.append(p)

        merged_result.hosts = list(host_map.values())
        merged_result.total_hosts = len(merged_result.hosts)
        merged_result.hosts_up = len([h for h in merged_result.hosts if h.state == 'up'])
        logger.info(f"Merged {len(xml_files)} reports into one with {merged_result.total_hosts} hosts.")
        return merged_result
        
    @staticmethod
    def _parse_scan_info(root: ET.Element) -> Dict[str, Any]:
        info = {attr: root.attrib.get(attr) for attr in ['scanner', 'version', 'startstr']}
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            info.update(scaninfo.attrib)
        return info

    @staticmethod
    def _parse_host(host_elem: ET.Element) -> Optional[Host]:
        """Parse host information from XML element."""
        status_elem = host_elem.find('status')
        if status_elem is None or status_elem.get('state') not in ('up', 'down'):
            return None # Skip hosts that weren't properly scanned
        
        ip_elem = host_elem.find('address[@addrtype="ipv4"]') or host_elem.find('address[@addrtype="ipv6"]')
        if ip_elem is None: return None
        ip_address = ip_elem.get('addr')

        hostname_elem = host_elem.find('hostnames/hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else None

        host = Host(ip_address=ip_address, hostname=hostname, state=status_elem.get('state'))

        ports_elem = host_elem.find('ports')
        if ports_elem:
            host.ports = [port for port in (NmapXMLParser._parse_port(p) for p in ports_elem.findall('port')) if port]

        os_match = host_elem.find('os/osmatch')
        if os_match is not None:
            host.os_info = os_match.get('name')

        return host
    
    @staticmethod
    def _parse_port(port_elem: ET.Element) -> Optional[Port]:
        """Parse port information from XML element."""
        try:
            state_elem = port_elem.find('state')
            if state_elem is None: return None

            service, version = None, None
            service_elem = port_elem.find('service')
            if service_elem is not None:
                service = service_elem.get('name')
                product = service_elem.get('product', '')
                service_version = service_elem.get('version', '')
                version = f"{product} {service_version}".strip()
            
            port = Port(
                number=int(port_elem.get('portid')),
                protocol=port_elem.get('protocol'),
                state=state_elem.get('state'),
                service=service,
                version=version
            )
            
            # Simple script parsing
            scripts = port_elem.findall('script')
            if scripts:
                port.extra_info['scripts'] = [{'id': s.get('id'), 'output': s.get('output')} for s in scripts]
            return port
        except (ValueError, TypeError) as e:
            logger.warning(f"Skipping malformed port element: {e}")
            return None