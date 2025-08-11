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
            
            # Initialize scan result
            scan_result = ScanResult()
            
            # Parse scan info
            scan_result.scan_info = NmapXMLParser._parse_scan_info(root)
            
            # Parse timing info
            if 'start' in root.attrib:
                scan_result.start_time = datetime.fromtimestamp(int(root.attrib['start']))
            
            # Parse hosts
            hosts = []
            for host_elem in root.findall('host'):
                host = NmapXMLParser._parse_host(host_elem)
                if host:
                    hosts.append(host)
            
            scan_result.hosts = hosts
            scan_result.total_hosts = len(hosts)
            scan_result.hosts_up = len([h for h in hosts if h.state == 'up'])
            
            # Try to get end time from runstats
            runstats = root.find('runstats')
            if runstats is not None:
                finished = runstats.find('finished')
                if finished is not None and 'time' in finished.attrib:
                    scan_result.end_time = datetime.fromtimestamp(int(finished.attrib['time']))
            
            logger.info(f"Parsed XML file: {scan_result.total_hosts} hosts, {scan_result.hosts_up} up")
            return scan_result
            
        except ET.ParseError as e:
            logger.error(f"XML parsing error: {e}")
            raise ValueError(f"Invalid XML file: {e}")
        except Exception as e:
            logger.error(f"Error parsing XML file {xml_file_path}: {e}")
            raise
    
    @staticmethod
    def _parse_scan_info(root: ET.Element) -> Dict[str, Any]:
        """Parse scan information from XML root."""
        scan_info = {}
        
        # Basic attributes
        for attr in ['scanner', 'version', 'start']:
            if attr in root.attrib:
                scan_info[attr] = root.attrib[attr]
        
        # Scan info element
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            scan_info.update(scaninfo.attrib)
        
        # Verbose info
        verbose = root.find('verbose')
        if verbose is not None:
            scan_info['verbose_level'] = verbose.attrib.get('level', '0')
        
        # Debug info
        debugging = root.find('debugging')
        if debugging is not None:
            scan_info['debug_level'] = debugging.attrib.get('level', '0')
        
        return scan_info
    
    @staticmethod
    def _parse_host(host_elem: ET.Element) -> Optional[Host]:
        """Parse host information from XML element."""
        try:
            # Get host state
            status = host_elem.find('status')
            if status is None:
                return None
            
            host_state = status.attrib.get('state', 'unknown')
            
            # Get IP address
            address_elem = host_elem.find('address[@addrtype="ipv4"]')
            if address_elem is None:
                address_elem = host_elem.find('address[@addrtype="ipv6"]')
            
            if address_elem is None:
                return None
            
            ip_address = address_elem.attrib['addr']
            
            # Get hostname
            hostname = None
            hostnames = host_elem.find('hostnames')
            if hostnames is not None:
                hostname_elem = hostnames.find('hostname')
                if hostname_elem is not None:
                    hostname = hostname_elem.attrib.get('name')
            
            # Create host object
            host = Host(ip_address=ip_address, hostname=hostname, state=host_state)
            
            # Parse ports
            ports = host_elem.find('ports')
            if ports is not None:
                for port_elem in ports.findall('port'):
                    port = NmapXMLParser._parse_port(port_elem)
                    if port:
                        host.ports.append(port)
            
            # Parse OS information
            os_elem = host_elem.find('os')
            if os_elem is not None:
                os_matches = os_elem.findall('osmatch')
                if os_matches:
                    # Get the best match
                    best_match = max(os_matches, 
                                   key=lambda x: int(x.attrib.get('accuracy', '0')))
                    host.os_info = best_match.attrib.get('name')
            
            # Parse additional host info
            host.extra_info = NmapXMLParser._parse_host_extra_info(host_elem)
            
            return host
            
        except Exception as e:
            logger.warning(f"Error parsing host element: {e}")
            return None
    
    @staticmethod
    def _parse_port(port_elem: ET.Element) -> Optional[Port]:
        """Parse port information from XML element."""
        try:
            port_number = int(port_elem.attrib['portid'])
            protocol = port_elem.attrib['protocol']
            
            # Get port state
            state_elem = port_elem.find('state')
            if state_elem is None:
                return None
            
            port_state = state_elem.attrib['state']
            
            # Get service information
            service = None
            version = None
            service_elem = port_elem.find('service')
            if service_elem is not None:
                service = service_elem.attrib.get('name')
                product = service_elem.attrib.get('product', '')
                service_version = service_elem.attrib.get('version', '')
                if product or service_version:
                    version = f"{product} {service_version}".strip()
            
            # Create port object
            port = Port(
                number=port_number,
                protocol=protocol,
                state=port_state,
                service=service,
                version=version
            )
            
            # Parse additional port information
            port.extra_info = NmapXMLParser._parse_port_extra_info(port_elem)
            
            return port
            
        except Exception as e:
            logger.warning(f"Error parsing port element: {e}")
            return None
    
    @staticmethod
    def _parse_host_extra_info(host_elem: ET.Element) -> Dict[str, Any]:
        """Parse additional host information."""
        extra_info = {}
        
        # Host scripts
        hostscript = host_elem.find('hostscript')
        if hostscript is not None:
            scripts = []
            for script_elem in hostscript.findall('script'):
                script_info = {
                    'id': script_elem.attrib.get('id'),
                    'output': script_elem.attrib.get('output', '').strip()
                }
                scripts.append(script_info)
            if scripts:
                extra_info['scripts'] = scripts
        
        # Uptime
        uptime = host_elem.find('uptime')
        if uptime is not None:
            extra_info['uptime'] = uptime.attrib
        
        # Distance
        distance = host_elem.find('distance')
        if distance is not None:
            extra_info['distance'] = distance.attrib.get('value')
        
        return extra_info
    
    @staticmethod
    def _parse_port_extra_info(port_elem: ET.Element) -> Dict[str, Any]:
        """Parse additional port information."""
        extra_info = {}
        
        # Service details
        service_elem = port_elem.find('service')
        if service_elem is not None:
            service_info = {}
            for attr in ['method', 'conf', 'extrainfo', 'tunnel', 'proto', 'rpcnum', 'lowver', 'highver']:
                if attr in service_elem.attrib:
                    service_info[attr] = service_elem.attrib[attr]
            
            if service_info:
                extra_info['service_details'] = service_info
        
        # Port scripts
        script_results = []
        for script_elem in port_elem.findall('script'):
            script_info = {
                'id': script_elem.attrib.get('id'),
                'output': script_elem.attrib.get('output', '').strip()
            }
            
            # Parse script elements (tables, etc.)
            elements = []
            for elem in script_elem:
                if elem.tag == 'elem':
                    elements.append({
                        'key': elem.attrib.get('key', ''),
                        'value': elem.text or ''
                    })
                elif elem.tag == 'table':
                    table_data = NmapXMLParser._parse_script_table(elem)
                    elements.append({
                        'type': 'table',
                        'key': elem.attrib.get('key', ''),
                        'data': table_data
                    })
            
            if elements:
                script_info['elements'] = elements
            
            script_results.append(script_info)
        
        if script_results:
            extra_info['scripts'] = script_results
        
        return extra_info
    
    @staticmethod
    def _parse_script_table(table_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parse script table elements."""
        table_data = []
        
        for elem in table_elem:
            if elem.tag == 'elem':
                table_data.append({
                    'key': elem.attrib.get('key', ''),
                    'value': elem.text or ''
                })
            elif elem.tag == 'table':
                # Nested table
                nested_table = NmapXMLParser._parse_script_table(elem)
                table_data.append({
                    'key': elem.attrib.get('key', ''),
                    'type': 'table',
                    'data': nested_table
                })
        
        return table_data
    
    @staticmethod
    def validate_xml_file(xml_file_path: str) -> bool:
        """Validate that the XML file is a valid Nmap output."""
        try:
            tree = ET.parse(xml_file_path)
            root = tree.getroot()
            
            # Check if it's an Nmap XML file
            if root.tag != 'nmaprun':
                return False
            
            # Check for required attributes
            required_attrs = ['scanner', 'start']
            for attr in required_attrs:
                if attr not in root.attrib:
                    return False
            
            return True
            
        except ET.ParseError:
            return False
        except Exception:
            return False
    
    @staticmethod
    def extract_web_services(scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Extract web services from scan results."""
        web_services = []
        
        for host in scan_result.hosts:
            if host.state != 'up':
                continue
                
            for port in host.ports:
                if port.state != 'open':
                    continue
                
                # Check if it's a web service
                is_web_service = False
                protocol = 'http'
                
                # Common web ports
                if port.number in [80, 8080, 8000, 8008, 8888]:
                    is_web_service = True
                    protocol = 'http'
                elif port.number in [443, 8443, 9443]:
                    is_web_service = True
                    protocol = 'https'
                
                # Check service name
                if port.service and any(web_svc in port.service.lower() 
                                      for web_svc in ['http', 'https', 'web', 'apache', 'nginx', 'iis']):
                    is_web_service = True
                    if 'https' in port.service.lower() or 'ssl' in port.service.lower():
                        protocol = 'https'
                
                # Check for SSL/TLS in extra info
                if port.extra_info:
                    scripts = port.extra_info.get('scripts', [])
                    for script in scripts:
                        if 'ssl' in script.get('id', '').lower() or 'tls' in script.get('id', '').lower():
                            protocol = 'https'
                            is_web_service = True
                            break
                
                if is_web_service:
                    web_service = {
                        'host': host.ip_address,
                        'hostname': host.hostname,
                        'port': port.number,
                        'protocol': protocol,
                        'service': port.service,
                        'version': port.version,
                        'url': f"{protocol}://{host.hostname or host.ip_address}:{port.number}"
                    }
                    web_services.append(web_service)
        
        return web_services