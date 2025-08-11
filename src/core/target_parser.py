"""Target parsing utilities."""

from typing import List, Set
from pathlib import Path
from ..models.target import Target
from ..utils.validators import Validators, ValidationError
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class TargetParser:
    """Parse targets from various input sources."""
    
    @staticmethod
    def parse_target_string(target_input: str) -> List[Target]:
        """Parse targets from a string input."""
        targets = []
        lines = target_input.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):  # Skip empty lines and comments
                continue
            
            try:
                ip_address, ports = Validators.parse_target_line(line)
                target = Target(ip_address=ip_address, ports=ports)
                targets.append(target)
                
            except ValidationError as e:
                logger.warning(f"Invalid target on line {line_num}: {e}")
                continue
        
        # Remove duplicates while preserving order
        seen = set()
        unique_targets = []
        for target in targets:
            target_key = (target.ip_address, tuple(target.ports) if target.ports else None)
            if target_key not in seen:
                seen.add(target_key)
                unique_targets.append(target)
        
        logger.info(f"Parsed {len(unique_targets)} unique targets from string input")
        return unique_targets
    
    @staticmethod
    def parse_target_file(file_path: str) -> List[Target]:
        """Parse targets from a text file."""
        if not Validators.validate_file_path(file_path):
            raise ValidationError(f"Invalid file path: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            targets = TargetParser.parse_target_string(content)
            logger.info(f"Parsed {len(targets)} targets from file: {file_path}")
            return targets
            
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    content = f.read()
                targets = TargetParser.parse_target_string(content)
                logger.info(f"Parsed {len(targets)} targets from file (latin-1): {file_path}")
                return targets
            except Exception as e:
                raise ValidationError(f"Could not read file {file_path}: {e}")
                
        except Exception as e:
            raise ValidationError(f"Error reading file {file_path}: {e}")
    
    @staticmethod
    def targets_to_nmap_format(targets: List[Target]) -> List[str]:
        """Convert Target objects to Nmap command format."""
        nmap_targets = []
        
        # Group targets by port specifications
        targets_without_ports = []
        targets_with_ports = {}
        
        for target in targets:
            if target.has_specific_ports:
                port_key = tuple(sorted(target.ports))
                if port_key not in targets_with_ports:
                    targets_with_ports[port_key] = []
                targets_with_ports[port_key].append(target.ip_address)
            else:
                targets_without_ports.append(target.ip_address)
        
        # Add targets without specific ports
        if targets_without_ports:
            nmap_targets.extend(targets_without_ports)
        
        # Add targets with specific ports (these need separate scans)
        # For now, we'll return them as separate entries
        # This might need adjustment based on how the scanner handles it
        for ports, ips in targets_with_ports.items():
            for ip in ips:
                nmap_targets.append(f"{ip} -p {','.join(map(str, ports))}")
        
        return nmap_targets
    
    @staticmethod
    def validate_targets(targets: List[Target]) -> List[str]:
        """Validate targets and return list of issues."""
        issues = []
        
        if not targets:
            issues.append("No targets provided")
            return issues
        
        # Check for duplicate IPs
        ip_counts = {}
        for target in targets:
            if target.ip_address in ip_counts:
                ip_counts[target.ip_address] += 1
            else:
                ip_counts[target.ip_address] = 1
        
        duplicates = [ip for ip, count in ip_counts.items() if count > 1]
        if duplicates:
            issues.append(f"Duplicate IP addresses found: {', '.join(duplicates)}")
        
        # Check for private/reserved IPs (warning, not error)
        private_ips = []
        for target in targets:
            try:
                import ipaddress
                ip = ipaddress.ip_address(target.ip_address)
                if ip.is_private or ip.is_reserved or ip.is_loopback:
                    private_ips.append(str(ip))
            except ValueError:
                pass
        
        if private_ips:
            issues.append(f"Warning: Private/reserved IP addresses detected: {', '.join(private_ips[:5])}")
        
        # Check for too many targets
        if len(targets) > 1000:
            issues.append(f"Warning: Large number of targets ({len(targets)}). Consider splitting the scan.")
        
        return issues