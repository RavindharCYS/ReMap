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
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.tls_versions = [
            ('TLSv1.0', ssl.PROTOCOL_TLSv1),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2),
        ]
        
        # Add TLSv1.3 if available (Python 3.7+)
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            self.tls_versions.append(('TLSv1.3', ssl.PROTOCOL_TLSv1_3))
    
    def analyze_tls(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Analyze TLS configuration for a host:port.
        
        Returns:
            Dictionary with TLS analysis results or None if failed
        """
        try:
            result = {
                'host': host,
                'port': port,
                'supported_versions': [],
                'preferred_cipher': None,
                'supported_ciphers': [],
                'weak_ciphers': [],
                'certificate_info': {},
                'vulnerabilities': [],
                'analysis_time': datetime.now()
            }
            
            # Test each TLS version
            for version_name, protocol in self.tls_versions:
                try:
                    if self._test_tls_version(host, port, protocol):
                        result['supported_versions'].append(version_name)
                        logger.debug(f"{host}:{port} supports {version_name}")
                except Exception as e:
                    logger.debug(f"TLS {version_name} test failed for {host}:{port}: {e}")
            
            if not result['supported_versions']:
                logger.info(f"No TLS versions supported on {host}:{port}")
                return None
            
            # Get cipher information using the highest supported version
            try:
                cipher_info = self._get_cipher_info(host, port)
                if cipher_info:
                    result.update(cipher_info)
            except Exception as e:
                logger.warning(f"Failed to get cipher info for {host}:{port}: {e}")
            
            # Get certificate information
            try:
                cert_info = self._get_certificate_info(host, port)
                if cert_info:
                    result['certificate_info'] = cert_info
            except Exception as e:
                logger.warning(f"Failed to get certificate info for {host}:{port}: {e}")
            
            # Analyze for vulnerabilities
            result['vulnerabilities'] = self._check_tls_vulnerabilities(result)
            
            return result
            
        except Exception as e:
            logger.error(f"TLS analysis failed for {host}:{port}: {e}")
            return None
    
    def _test_tls_version(self, host: str, port: int, protocol) -> bool:
        """Test if a specific TLS version is supported."""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return True
                    
        except ssl.SSLError:
            return False
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return False
    
    def _get_cipher_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Get cipher suite information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name, tls_version, key_bits = cipher
                        
                        # Get all supported ciphers (this is a simplified approach)
                        supported_ciphers = [cipher_name]
                        weak_ciphers = self._identify_weak_ciphers(supported_ciphers)
                        
                        return {
                            'preferred_cipher': cipher_name,
                            'tls_version_used': tls_version,
                            'key_bits': key_bits,
                            'supported_ciphers': supported_ciphers,
                            'weak_ciphers': weak_ciphers
                        }
                        
        except Exception as e:
            logger.debug(f"Failed to get cipher info for {host}:{port}: {e}")
        
        return None
    
    def _get_certificate_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Parse certificate information
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        
                        # Parse dates
                        not_before = None
                        not_after = None
                        
                        try:
                            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        except (ValueError, KeyError):
                            pass
                        
                        return {
                            'subject': subject,
                            'issuer': issuer,
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': not_before,
                            'not_after': not_after,
                            'subject_alt_names': cert.get('subjectAltName', []),
                            'is_self_signed': subject.get('commonName') == issuer.get('commonName')
                        }
                        
        except Exception as e:
            logger.debug(f"Failed to get certificate info for {host}:{port}: {e}")
        
        return None
    
    def _identify_weak_ciphers(self, ciphers: List[str]) -> List[str]:
        """Identify weak cipher suites."""
        weak_patterns = [
            'NULL', 'EXPORT', 'DES', '3DES', 'MD5', 'RC4', 'RC2',
            'ADH', 'AECDH', 'LOW', 'EXP', 'aNULL', 'eNULL'
        ]
        
        weak_ciphers = []
        for cipher in ciphers:
            cipher_upper = cipher.upper()
            if any(pattern in cipher_upper for pattern in weak_patterns):
                weak_ciphers.append(cipher)
        
        return weak_ciphers
    
    def _check_tls_vulnerabilities(self, tls_result: Dict[str, Any]) -> List[str]:
        """Check for known TLS vulnerabilities."""
        vulnerabilities = []
        supported_versions = tls_result.get('supported_versions', [])
        
        # Check for deprecated versions
        if 'TLSv1.0' in supported_versions:
            vulnerabilities.append('TLS 1.0 supported (deprecated)')
        
        if 'TLSv1.1' in supported_versions:
            vulnerabilities.append('TLS 1.1 supported (deprecated)')
        
        # Check for weak ciphers
        weak_ciphers = tls_result.get('weak_ciphers', [])
        if weak_ciphers:
            vulnerabilities.append(f'Weak cipher suites: {", ".join(weak_ciphers)}')
        
        # Check certificate issues
        cert_info = tls_result.get('certificate_info', {})
        if cert_info.get('is_self_signed'):
            vulnerabilities.append('Self-signed certificate')
        
        not_after = cert_info.get('not_after')
        if not_after and not_after < datetime.now():
            vulnerabilities.append('Certificate expired')
        elif not_after and (not_after - datetime.now()).days < 30:
            days_left = (not_after - datetime.now()).days
            vulnerabilities.append(f'Certificate expires in {days_left} days')
        
        return vulnerabilities

    def bulk_analyze(self, targets: List[tuple], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Analyze multiple TLS targets concurrently."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.analyze_tls, host, port): (host, port)
                for host, port in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                host, port = future_to_target[future]
                try:
                    result = future.result(timeout=30)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"TLS analysis failed for {host}:{port}: {e}")
        
        return results