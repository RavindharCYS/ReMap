"""Nmap command wrapper for executing scans."""

import subprocess
import shlex
import tempfile
import os
from typing import List, Dict, Optional, Any
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
        # Common paths for Nmap
        common_paths = [
            "nmap",  # In PATH
            "/usr/bin/nmap",  # Linux
            "/usr/local/bin/nmap",  # macOS
            "C:\\Program Files (x86)\\Nmap\\nmap.exe",  # Windows
            "C:\\Program Files\\Nmap\\nmap.exe",  # Windows 64-bit
        ]
        
        for path in common_paths:
            try:
                result = subprocess.run([path, "--version"], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    logger.info(f"Found Nmap at: {path}")
                    return path
            except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
                continue
        
        raise FileNotFoundError("Nmap not found. Please install Nmap and ensure it's in your PATH.")
    
    def build_command(self, targets: List[str], scan_type: str = "fast", 
                     output_file: Optional[str] = None) -> List[str]:
        """Build Nmap command based on parameters."""
        cmd = [self.nmap_path]
        
        # Basic options
        cmd.extend(["-T4"])  # Timing template
        
        # Scan type specific options
        if scan_type == "fast":
            cmd.extend(["-F"])  # Fast scan
        elif scan_type == "1000":
            cmd.extend(["--top-ports", "1000"])
        elif scan_type == "all":
            cmd.extend(["-p-"])  # All ports
        
        # Service and version detection
        if self.settings.enable_service_detection:
            cmd.append("-sV")
        
        if self.settings.enable_version_detection:
            cmd.append("-sC")
        
        if self.settings.enable_os_detection:
            cmd.append("-O")
        
        if self.settings.enable_script_scan:
            cmd.append("-A")
        
        # Rate limiting
        if self.settings.enable_rate_limit:
            cmd.extend(["--max-rate", str(self.settings.rate_limit_value)])
        
        # Timing options
        if self.settings.scan_delay > 0:
            cmd.extend(["--scan-delay", f"{self.settings.scan_delay}s"])
        
        # Output options
        if output_file:
            cmd.extend(["-oX", output_file])
        
        if self.settings.verbose_output:
            cmd.append("-v")
        
        # Targets
        cmd.extend(targets)
        
        logger.debug(f"Built Nmap command: {' '.join(cmd)}")
        return cmd
    
    def execute_scan(self, targets: List[str], scan_type: str = "fast",
                    progress_callback=None) -> Dict[str, Any]:
        """Execute Nmap scan and return results."""
        
        # Create temporary XML output file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as tmp_file:
            xml_output_file = tmp_file.name
        
        try:
            # Build command
            cmd = self.build_command(targets, scan_type, xml_output_file)
            
            logger.info(f"Starting Nmap scan: {' '.join(cmd)}")
            
            # Execute command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                universal_newlines=True
            )
            
            # Monitor progress
            stdout_lines = []
            stderr_lines = []
            
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                
                if output:
                    stdout_lines.append(output.strip())
                    if progress_callback:
                        progress_callback(output.strip())
                
                # Check for errors
                error = process.stderr.readline()
                if error:
                    stderr_lines.append(error.strip())
            
            # Get remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            if remaining_stdout:
                stdout_lines.extend(remaining_stdout.strip().split('\n'))
            if remaining_stderr:
                stderr_lines.extend(remaining_stderr.strip().split('\n'))
            
            return_code = process.returncode
            
            result = {
                'return_code': return_code,
                'stdout': stdout_lines,
                'stderr': stderr_lines,
                'xml_file': xml_output_file if return_code == 0 else None,
                'command': ' '.join(cmd)
            }
            
            if return_code == 0:
                logger.info("Nmap scan completed successfully")
            else:
                logger.error(f"Nmap scan failed with return code: {return_code}")
                logger.error(f"Error output: {' '.join(stderr_lines)}")
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return {
                'return_code': -1,
                'stdout': [],
                'stderr': ['Scan timed out'],
                'xml_file': None,
                'command': ' '.join(cmd) if 'cmd' in locals() else ''
            }
        except Exception as e:
            logger.error(f"Error executing Nmap scan: {e}")
            return {
                'return_code': -1,
                'stdout': [],
                'stderr': [str(e)],
                'xml_file': None,
                'command': ' '.join(cmd) if 'cmd' in locals() else ''
            }
        finally:
            # Cleanup temporary file if scan failed
            if os.path.exists(xml_output_file):
                try:
                    # Check if file has content
                    if os.path.getsize(xml_output_file) == 0:
                        os.unlink(xml_output_file)
                except OSError:
                    pass
    
    def test_nmap(self) -> bool:
        """Test if Nmap is working correctly."""
        try:
            result = subprocess.run([self.nmap_path, "--version"], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False