"""Input validation utilities."""

import ipaddress
from typing import List, Tuple, Optional
from pathlib import Path

class ValidationError(Exception):
    """Custom validation exception for parsing errors."""
    pass

class Validators:
    """Collection of input validation static methods."""
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate if a string is a valid IP address or CIDR network."""
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate if a number is a valid port."""
        return 1 <= port <= 65535

    @staticmethod
    def parse_target_line(line: str) -> Tuple[str, Optional[List[int]]]:
        """
        Parse a single target line like 'IP' or 'IP:port1,port2'.
        Returns (ip_address_or_network, list_of_ports_or_None)
        Raises ValidationError on failure.
        """
        line = line.strip()
        if not line:
            raise ValidationError("Line is empty.")
        
        if ':' in line and not any(c in 'abcdef' for c in line.lower()): # Basic check to avoid IPv6 address split
            parts = line.split(':', 1)
            ip_part, port_part = parts[0], parts[1]
            if not Validators.validate_ip(ip_part):
                raise ValidationError(f"Invalid IP or network: '{ip_part}'")

            ports = []
            try:
                for port_str in port_part.split(','):
                    port = int(port_str.strip())
                    if not Validators.validate_port(port):
                        raise ValidationError(f"Invalid port number: {port}")
                    ports.append(port)
                if not ports: raise ValueError # must have at least one port if colon is present
                return ip_part, ports
            except (ValueError, TypeError):
                raise ValidationError(f"Invalid port format: '{port_part}'")
        else: # No ports specified, just IP, CIDR, or range
            if not Validators.validate_ip(line):
                # Could be a range, let nmap handle it, just do basic checks
                if '-' in line and line.count('.') >= 3:
                     pass # Assume it's a valid range like 192.168.1.1-100
                else: # Could be a hostname or invalid
                     pass # Let nmap handle hostnames
            return line, None
            
    @staticmethod
    def validate_xml_file(file_path: str) -> bool:
        """Validate an XML file exists and seems readable."""
        p = Path(file_path)
        return p.exists() and p.is_file() and p.suffix.lower() == '.xml' and os.access(p, os.R_OK)