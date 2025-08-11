"""TLS version and configuration analyzer."""

import ssl
import socket
import concurrent.futures
from typing import Dict, List, Any, Optional
from datetime import datetime

from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class TLSAnalyzer:
    """Analyzer for TLS services and configurations."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.tls_protocols = {
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': getattr(ssl, 'PROTOCOL_TLSv1_3', None),
        }
    
    def analyze_tls(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Analyze TLS configuration for a host:port."""
        supported_versions = []
        for name, protocol in self.tls_protocols.items():
            if protocol is not None and self._test_tls_version(host, port, protocol):
                supported_versions.append(name)

        if not supported_versions:
            return None

        result = {
            'host': host,
            'port': port,
            'supported_versions': supported_versions,
            'analysis_time': datetime.now(),
            'vulnerabilities': []
        }
        
        result['vulnerabilities'] = self._check_tls_vulnerabilities(result)
        return result
    
    def _test_tls_version(self, host: str, port: int, protocol) -> bool:
        """Test if a specific TLS version is supported."""
        context = ssl.SSLContext(protocol)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            return False
        except Exception as e:
            logger.debug(f"TLS check failed for {host}:{port} with proto {protocol}: {e}")
            return False
            
    def _check_tls_vulnerabilities(self, tls_result: Dict[str, Any]) -> List[str]:
        """Check for known TLS vulnerabilities."""
        vulnerabilities = []
        versions = tls_result.get('supported_versions', [])
        
        if 'TLSv1.0' in versions:
            vulnerabilities.append('TLS 1.0 supported (deprecated)')
        if 'TLSv1.1' in versions:
            vulnerabilities.append('TLS 1.1 supported (deprecated)')

        # In a real tool, we'd test ciphers here too
        # but that is a more complex task.
        return vulnerabilities

    def bulk_analyze(self, targets: List[tuple], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Analyze multiple TLS targets concurrently."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(self.analyze_tls, h, p): (h, p) for h, p in targets}
            for future in concurrent.futures.as_completed(future_to_target):
                result = future.result()
                if result:
                    results.append(result)
        return results