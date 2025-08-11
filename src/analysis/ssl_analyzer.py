"""SSL certificate analyzer."""

import ssl
import socket
import OpenSSL.crypto
from typing import Dict, Any, Optional, List
from datetime import datetime
import concurrent.futures

from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SSLAnalyzer:
    """Analyzer for SSL certificates and configurations."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def analyze_certificate(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Analyze SSL certificate for a host:port.
        
        Returns:
            Dictionary with SSL analysis results or None if failed
        """
        try:
            result = {
                'host': host,
                'port': port,
                'certificate': {},
                'chain_info': {},
                'sslv3_supported': False,
                'vulnerabilities': [],
                'analysis_time': datetime.now()
            }
            
            # Get certificate information
            cert_info = self._get_detailed_certificate_info(host, port)
            if cert_info:
                result['certificate'] = cert_info
            
            # Test for SSLv3 support
            result['sslv3_supported'] = self._test_sslv3_support(host, port)
            
            # Get certificate chain information
            chain_info = self._get_certificate_chain(host, port)
            if chain_info:
                result['chain_info'] = chain_info
            
            # Analyze for vulnerabilities
            result['vulnerabilities'] = self._check_ssl_vulnerabilities(result)
            
            return result
            
        except Exception as e:
            logger.error(f"SSL analysis failed for {host}:{port}: {e}")
            return None
    
    def _get_detailed_certificate_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Get detailed certificate information using OpenSSL."""
        try:
            # Get certificate using standard SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    
                    if der_cert:
                        # Parse with OpenSSL for more detailed info
                        cert = OpenSSL.crypto.load_certificate(
                            OpenSSL.crypto.FILETYPE_ASN1, der_cert
                        )
                        
                        return self._parse_openssl_certificate(cert)
                        
        except Exception as e:
            logger.debug(f"Failed to get detailed certificate info for {host}:{port}: {e}")
            
            # Fallback to basic SSL certificate info
            try:
                return self._get_basic_certificate_info(host, port)
            except Exception as fallback_error:
                logger.debug(f"Fallback certificate info failed: {fallback_error}")
        
        return None
    
    def _parse_openssl_certificate(self, cert) -> Dict[str, Any]:
        """Parse OpenSSL certificate object."""
        try:
            # Basic certificate info
            subject = cert.get_subject()
            issuer = cert.get_issuer()
            
            # Convert dates
            not_before = datetime.strptime(
                cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'
            )
            not_after = datetime.strptime(
                cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'
            )
            
            # Subject and issuer details
            subject_dict = {
                component[0].decode(): component[1].decode()
                for component in subject.get_components()
            }
            issuer_dict = {
                component[0].decode(): component[1].decode()
                for component in issuer.get_components()
            }
            
            # Extensions
            extensions = {}
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                extensions[ext.get_short_name().decode()] = str(ext)
            
            return {
                'subject': subject_dict,
                'issuer': issuer_dict,
                'version': cert.get_version() + 1,  # OpenSSL uses 0-based versioning
                'serial_number': str(cert.get_serial_number()),
                'signature_algorithm': cert.get_signature_algorithm().decode(),
                'not_before': not_before,
                'not_after': not_after,
                'expiry_date': not_after,
                'days_until_expiry': (not_after - datetime.now()).days,
                'is_expired': datetime.now() > not_after,
                'is_self_signed': subject_dict == issuer_dict,
                'key_size': cert.get_pubkey().bits(),
                'extensions': extensions,
                'has_expired': cert.has_expired(),
                'fingerprint_sha1': cert.digest('sha1').decode(),
                'fingerprint_sha256': cert.digest('sha256').decode()
            }
            
        except Exception as e:
            logger.error(f"Error parsing OpenSSL certificate: {e}")
            return {}
    
    def _get_basic_certificate_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Get basic certificate information using standard SSL."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    if cert:
                        # Parse basic certificate info
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        
                        # Parse dates
                        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        
                        return {
                            'subject': subject,
                            'issuer': issuer,
                            'version': cert.get('version'),
                            'serial_number': cert.get('serialNumber'),
                            'not_before': not_before,
                            'not_after': not_after,
                            'expiry_date': not_after,
                            'days_until_expiry': (not_after - datetime.now()).days,
                            'is_expired': datetime.now() > not_after,
                            'is_self_signed': subject.get('commonName') == issuer.get('commonName'),
                            'subject_alt_names': cert.get('subjectAltName', [])
                        }
                        
        except Exception as e:
            logger.debug(f"Failed to get basic certificate info for {host}:{port}: {e}")
        
        return None
    
    def _test_sslv3_support(self, host: str, port: int) -> bool:
        """Test if SSLv3 is supported (POODLE vulnerability)."""
        try:
            # Note: SSLv3 might not be available in newer Python versions
            if hasattr(ssl, 'PROTOCOL_SSLv3'):
                context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((host, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        return True
            else:
                logger.debug("SSLv3 not available in this Python version")
                return False
                
        except ssl.SSLError:
            return False
        except (socket.timeout, socket.error, ConnectionRefusedError):
            return False
    
    def _get_certificate_chain(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Get certificate chain information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get the certificate chain
                    cert_chain = ssock.getpeercert_chain()
                    
                    if cert_chain:
                        chain_info = {
                            'chain_length': len(cert_chain),
                            'certificates': []
                        }
                        
                        for i, cert_der in enumerate(cert_chain):
                            try:
                                cert = OpenSSL.crypto.load_certificate(
                                    OpenSSL.crypto.FILETYPE_ASN1, cert_der
                                )
                                
                                subject = {
                                    component[0].decode(): component[1].decode()
                                    for component in cert.get_subject().get_components()
                                }
                                
                                chain_info['certificates'].append({
                                    'position': i,
                                    'subject': subject,
                                    'is_ca': 'CA:TRUE' in str(cert.get_extension(0)) if cert.get_extension_count() > 0 else False
                                })
                                
                            except Exception as cert_error:
                                logger.debug(f"Error parsing certificate {i} in chain: {cert_error}")
                        
                        return chain_info
                        
        except Exception as e:
            logger.debug(f"Failed to get certificate chain for {host}:{port}: {e}")
        
        return None
    
    def _check_ssl_vulnerabilities(self, ssl_result: Dict[str, Any]) -> List[str]:
        """Check for SSL vulnerabilities."""
        vulnerabilities = []
        
        # Check SSLv3 support (POODLE)
        if ssl_result.get('sslv3_supported', False):
            vulnerabilities.append('SSLv3 supported (POODLE vulnerability)')
        
        cert_info = ssl_result.get('certificate', {})
        
        # Check certificate expiry
        if cert_info.get('is_expired', False):
            vulnerabilities.append('Certificate has expired')
        else:
            days_until_expiry = cert_info.get('days_until_expiry', 0)
            if 0 < days_until_expiry <= 30:
                vulnerabilities.append(f'Certificate expires in {days_until_expiry} days')
        
        # Check self-signed certificate
        if cert_info.get('is_self_signed', False):
            vulnerabilities.append('Self-signed certificate')
        
        # Check weak key size
        key_size = cert_info.get('key_size', 0)
        if key_size > 0 and key_size < 2048:
            vulnerabilities.append(f'Weak key size: {key_size} bits')
        
        # Check weak signature algorithm
        sig_alg = cert_info.get('signature_algorithm', '').lower()
        if any(weak_alg in sig_alg for weak_alg in ['md5', 'sha1']):
            vulnerabilities.append(f'Weak signature algorithm: {sig_alg}')
        
        return vulnerabilities
    
    def bulk_analyze(self, targets: List[tuple], max_workers: int = 5) -> List[Dict[str, Any]]:
        """Analyze multiple SSL targets concurrently."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.analyze_certificate, host, port): (host, port)
                for host, port in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                host, port = future_to_target[future]
                try:
                    result = future.result(timeout=45)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"SSL analysis failed for {host}:{port}: {e}")
        
        return results