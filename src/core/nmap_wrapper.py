"""Nmap command wrapper for executing scans."""

import subprocess
import shlex
import os
from typing import List, Dict, Optional, Any, Callable
from pathlib import Path

from ..utils.logger import setup_logger
from ..models.settings import ScanSettings

logger = setup_logger(__name__)

class NmapWrapper:
    """Wrapper for Nmap command execution."""
    
    def __init__(self, settings: ScanSettings):
        self.settings = settings
        self.nmap_path = self._find_nmap()
        
    def _find_nmap(self) -> str:
        """Find Nmap executable path."""
        # This function seems to be working well, no changes needed.
        if hasattr(self.settings, 'nmap_path') and self.settings.nmap_path and Path(self.settings.nmap_path).is_file():
            logger.info(f"Using user-defined Nmap path: {self.settings.nmap_path}")
            return self.settings.nmap_path
            
        common_paths = [
            "nmap", "/usr/bin/nmap", "/usr/local/bin/nmap",
            "C:\\Program Files (x86)\\Nmap\\nmap.exe", "C:\\Program Files\\Nmap\\nmap.exe",
        ]
        
        for path in common_paths:
            try:
                result = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
                if result.returncode == 0 and "Nmap version" in result.stdout:
                    logger.info(f"Found Nmap at: {path}")
                    return path
            except (FileNotFoundError, subprocess.SubprocessError):
                continue
        
        raise FileNotFoundError("Nmap not found. Please install Nmap and ensure it is in your PATH, or specify the path in Settings.")
    
    def build_command(self, targets: List[str], scan_type: str, 
                     output_file: str, ports: Optional[List[int]] = None) -> List[str]:
        """Build Nmap command based on parameters."""
        cmd = [self.nmap_path]
        
        # Add the new Host Discovery option
        if getattr(self.settings, 'disable_host_discovery', True): # Default to True
            cmd.append("-Pn")

        cmd.extend(["-T" + str(getattr(self.settings, 'timing_template', 4))])

        if ports:
            cmd.extend(["-p", ",".join(map(str, ports))])
        elif scan_type == "fast":
            cmd.append("-F")
        elif scan_type == "1000":
            cmd.extend(["--top-ports", "1000"])
        elif scan_type == "all":
            cmd.append("-p-")
        
        if self.settings.enable_aggressive_scan:
            cmd.append("-A")
        else:
            if self.settings.enable_service_detection:
                cmd.append("-sV")
            if self.settings.enable_script_scan:
                cmd.append("-sC")
            if self.settings.enable_os_detection:
                cmd.append("-O")

        if self.settings.enable_rate_limit:
            cmd.extend(["--max-rate", str(self.settings.rate_limit_value)])
        
        if self.settings.scan_delay > 0:
            cmd.extend(["--scan-delay", f"{self.settings.scan_delay}s"])
            
        cmd.extend(["-oX", output_file])
        if self.settings.verbose_output:
            cmd.append("-v")

        if self.settings.enable_os_detection and os.name != 'nt' and os.geteuid() != 0:
            logger.warning("OS Detection (-O) may require root/administrator privileges.")

        cmd.extend(targets)
        logger.debug(f"Built Nmap command: {' '.join(shlex.quote(c) for c in cmd)}")
        return cmd

    def execute_scan(self, targets: List[str], scan_type: str, output_file: str,
                     ports: Optional[List[int]] = None,
                     progress_callback: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
        """Execute Nmap scan and return results."""
        # This function is working well, no changes needed here.
        cmd = self.build_command(targets, scan_type, output_file, ports)
        logger.info(f"Executing Nmap: {' '.join(shlex.quote(c) for c in cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace', universal_newlines=True
            )
            
            if progress_callback:
                for line in iter(process.stdout.readline, ''):
                    if line: progress_callback(line.strip())

            stdout, stderr = process.communicate(timeout=self.settings.timeout)
            if progress_callback and stdout:
                for line in stdout.splitlines():
                    if line: progress_callback(line.strip())

            if process.returncode != 0:
                logger.error(f"Nmap scan failed with code {process.returncode}")
                logger.error(f"Nmap stderr: {stderr}")

            return { 'return_code': process.returncode, 'stdout': stdout, 'stderr': stderr,
                'xml_file': output_file if process.returncode == 0 else None }

        except FileNotFoundError:
            msg = "Nmap executable not found."
            logger.error(msg)
            return {'return_code': -1, 'stderr': msg, 'xml_file': None}
        except subprocess.TimeoutExpired:
            process.kill()
            msg = f"Nmap scan timed out after {self.settings.timeout} seconds."
            logger.error(msg)
            return {'return_code': -1, 'stderr': msg, 'xml_file': None}
        except Exception as e:
            logger.error(f"Error executing Nmap scan: {e}", exc_info=True)
            return {'return_code': -1, 'stderr': str(e), 'xml_file': None}