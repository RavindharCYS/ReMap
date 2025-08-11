"""Target parsing utilities."""

from typing import List
from ..models.target import Target
from ..utils.validators import Validators, ValidationError
from ..utils.logger import setup_logger
from ..utils.file_handler import FileHandler

logger = setup_logger(__name__)

class TargetParser:
    """Parse targets from various input sources."""
    
    @staticmethod
    def parse_target_string(target_input: str) -> List[Target]:
        """Parse targets from a string input, handling various formats like ranges and CIDR."""
        targets = []
        seen = set()
        
        for line in target_input.strip().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            try:
                # This logic should be expanded to handle ranges (e.g., 192.168.1.1-100) and CIDR
                # For now, we rely on the validator for simple 'IP' or 'IP:port,port' format.
                ip, ports = Validators.parse_target_line(line)
                target = Target(ip_address=ip, ports=ports)
                target_key = str(target) # Use string representation for uniqueness
                if target_key not in seen:
                    targets.append(target)
                    seen.add(target_key)
            except ValidationError as e:
                logger.warning(f"Skipping invalid target '{line}': {e}")
                
        logger.info(f"Parsed {len(targets)} unique targets from string.")
        return targets

    @staticmethod
    def parse_target_file(file_path: str) -> List[Target]:
        """Parse targets from a text file."""
        content = FileHandler.read_text_file(file_path)
        if content is None:
            raise ValidationError(f"Could not read or decode target file: {file_path}")
        
        return TargetParser.parse_target_string(content)

    @staticmethod
    def validate_targets(targets: List[Target]) -> List[str]:
        """Validate a list of targets and return potential issues."""
        issues = []
        if not targets:
            return ["No targets provided."]

        if len(targets) > 1024:
            issues.append(f"Warning: Large scan detected ({len(targets)} targets). This may take a long time.")
        
        # In a real-world scenario, you might add checks for non-routable IPs, etc.
        return issues