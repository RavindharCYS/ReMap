"""Input validation utilities."""

import re
import ipaddress
from typing import List, Tuple, Optional
from pathlib import Path

class ValidationError(Exception):
    """Custom validation exception."""
    pass

class Validators:
    """Collection of input validators."""
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number."""
        return 1 <= port <= 65535
    
    @staticmethod
    def validate_port_range(port_range: str) -> bool:
        """Validate port range format (e.g., '80-443')."""
        try:
            if '-' in port_range:
                start, end = map(int, port_range.split('-'))
                return Validators.validate_port(start) and Validators.validate_port(end) and start <= end
            else:
                return Validators.validate_port(int(port_range))
        except ValueError:
            return False
    
    @staticmethod
    def parse_target_line(line: str) -> Tuple[str, Optional[List[int]]]:
        """
        Parse a target line in format 'IP' or 'IP:PORT1,PORT2'.
        Returns (ip_address, ports_list)
        """
        line = line.strip()
        if not line:
            raise ValidationError("Empty line")
        
        if ':' in line:
            ip_part, port_part = line.split(':', 1)
            
            # Validate IP
            if not Validators.validate_ip_address(ip_part):
                raise ValidationError(f"Invalid IP address: {ip_part}")
            
            # Parse ports
            ports = []
            for port_str in port_part.split(','):
                port_str = port_str.strip()
                try:
                    port = int(port_str)
                    if not Validators.validate_port(port):
                        raise ValidationError(f"Invalid port: {port}")
                    ports.append(port)
                except ValueError:
                    raise ValidationError(f"Invalid port format: {port_str}")
            
            return ip_part, ports
        else:
            # Just IP address
            if not Validators.validate_ip_address(line):
                raise ValidationError(f"Invalid IP address: {line}")
            return line, None
    
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        """Validate file path exists and is readable."""
        path = Path(file_path)
        return path.exists() and path.is_file() and path.suffix.lower() == '.txt'
    
    @staticmethod
    def validate_xml_file(file_path: str) -> bool:
        """Validate XML file exists and has correct extension."""
        path = Path(file_path)
        return path.exists() and path.is_file() and path.suffix.lower() == '.xml'