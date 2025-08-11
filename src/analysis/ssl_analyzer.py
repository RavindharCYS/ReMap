"""SSL certificate analyzer."""

import ssl
import socket
from OpenSSL import crypto
from typing import Dict, Any, Optional, List
from datetime import datetime
import concurrent.futures

from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SSLAnalyzer:
    """Analyzer for SSL certificates and configurations."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def analyze_certificate(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Analyze SSL certificate for a host:port."""
        result = {'host': host, 'port': port}
        cert_info = self._get_certificate_info(host, port)
        if not cert_info:
            return None
        result['certificate'] = cert_info
        
        # Test for SSLv3 support
        result['sslv3_supported'] = self._test_sslv3_support(host, port)
        
        result['vulnerabilities'] = self._check_ssl_vulnerabilities(result)
        return result

    def _get_certificate_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Get certificate information using OpenSSL for detail."""
        try:
            cert_pem = ssl.get_server_certificate((host, port), timeout=self.timeout)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
            return self._parse_openssl_certificate(cert)
        except Exception as e:
            logger.debug(f"Failed to get certificate for {host}:{port}: {e}")
            return None

    def _parse_openssl_certificate(self, cert) -> Dict[str, Any]:
        """Parse an OpenSSL certificate object into a dictionary."""
        subject = {k.decode(): v.decode() for k, v in cert.get_subject().get_components()}
        issuer = {k.decode(): v.decode() for k, v in cert.get_issuer().get_components()}
        
        not_after_str = cert.get_notAfter().decode('ascii')
        expiry_date = datetime.strptime(not_after_str, '%Y%m%d%H%M%SZ')

        return {
            'subject': subject,
            'issuer': issuer,
            'serial_number': str(cert.get_serial_number()),
            'signature_algorithm': cert.get_signature_algorithm().decode(),
            'expiry_date': expiry_date,
            'days_until_expiry': (expiry_date - datetime.utcnow()).days,
            'is_expired': cert.has_expired(),
            'is_self_signed': subject == issuer,
            'key_size': cert.get_pubkey().bits(),
            'fingerprint_sha256': cert.digest('sha256').decode(),
        }

    def _test_sslv3_support(self, host: str, port: int) -> bool:
        """Test if SSLv3 is supported (POODLE vulnerability)."""
        # Note: SSLv3 is deprecated and often disabled at the OS/library level.
        # This check might return False even if the server supports it, if the client doesn't.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.SSLv3
        context.maximum_version = ssl.TLSVersion.SSLv3
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return "SSLv3" in ssock.version()
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError):
            return False
        except Exception as e:
            logger.debug(f"SSLv3 check failed for {host}:{port} - {e}")
            return False

    def _check_ssl_vulnerabilities(self, ssl_result: Dict[str, Any]) -> List[str]:
        """Check for SSL vulnerabilities based on the analysis."""
        vulnerabilities = []
        if ssl_result.get('sslv3_supported'):
            vulnerabilities.append('SSLv3 supported (POODLE)')
        
        cert = ssl_result.get('certificate', {})
        if not cert: return vulnerabilities
        
        if cert['is_expired']:
            vulnerabilities.append('Certificate has expired')
        elif 0 <= cert['days_until_expiry'] <= 30:
            vulnerabilities.append(f"Certificate expires in {cert['days_until_expiry']} days")
        
        if cert['is_self_signed']:
            vulnerabilities.append('Self-signed certificate in use')
        
        if cert['key_size'] < 2048:
            vulnerabilities.append(f"Weak key size: {cert['key_size']}-bit")
            
        sig_alg = cert.get('signature_algorithm', '').lower()
        if 'md5' in sig_alg or 'sha1' in sig_alg:
            vulnerabilities.append(f'Weak signature algorithm: {sig_alg}')
            
        return vulnerabilities

    def bulk_analyze(self, targets: List[tuple], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Analyze multiple SSL targets concurrently."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(self.analyze_certificate, h, p): (h,p) for h, p in targets}
            for future in concurrent.futures.as_completed(future_to_target):
                result = future.result()
                if result:
                    results.append(result)
        return results