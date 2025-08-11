"""Main security analysis coordinator."""

from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import concurrent.futures
import threading

from .tls_analyzer import TLSAnalyzer
from .ssl_analyzer import SSLAnalyzer
from .smb_analyzer import SMBAnalyzer
from .web_detector import WebDetector
from ..models.scan_result import ScanResult, Host
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SecurityAnalysisResult:
    """Container for security analysis results."""
    
    def __init__(self):
        self.tls_results = []
        self.ssl_results = []
        self.smb_results = []
        self.web_services = []
        self.vulnerabilities = []
        self.analysis_time = None
        self.total_checks = 0
        self.completed_checks = 0
    
    def add_vulnerability(self, host: str, port: int, vulnerability: str, 
                         severity: str = "medium", details: str = ""):
        """Add a vulnerability finding."""
        self.vulnerabilities.append({
            'host': host,
            'port': port,
            'vulnerability': vulnerability,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now()
        })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'tls_checks': len(self.tls_results),
            'ssl_checks': len(self.ssl_results),
            'smb_checks': len(self.smb_results),
            'web_services_found': len(self.web_services),
            'analysis_duration': self.analysis_time
        }

class SecurityAnalyzer:
    """Main security analysis coordinator."""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.tls_analyzer = TLSAnalyzer()
        self.ssl_analyzer = SSLAnalyzer()
        self.smb_analyzer = SMBAnalyzer()
        self.web_detector = WebDetector()
        
        self.cancel_event = threading.Event()
        self.progress_callback = None
    
    def set_progress_callback(self, callback):
        """Set progress callback function."""
        self.progress_callback = callback
    
    def analyze_scan_results(self, scan_result: ScanResult, 
                           analysis_options: Dict[str, bool]) -> SecurityAnalysisResult:
        """
        Perform comprehensive security analysis on scan results.
        
        Args:
            scan_result: ScanResult object from Nmap scan
            analysis_options: Dictionary of analysis options to enable/disable
        """
        start_time = datetime.now()
        result = SecurityAnalysisResult()
        self.cancel_event.clear()
        
        try:
            # Get all hosts that are up
            active_hosts = [host for host in scan_result.hosts if host.state == 'up']
            
            if not active_hosts:
                logger.warning("No active hosts found for analysis")
                return result
            
            self._send_progress(f"Starting security analysis of {len(active_hosts)} hosts")
            
            # Calculate total checks for progress tracking
            total_checks = self._calculate_total_checks(active_hosts, analysis_options)
            result.total_checks = total_checks
            
            # Perform different types of analysis
            if analysis_options.get('tls_check', False):
                self._analyze_tls_services(active_hosts, result)
            
            if analysis_options.get('ssl_check', False):
                self._analyze_ssl_certificates(active_hosts, result)
            
            if analysis_options.get('smb_check', False):
                self._analyze_smb_services(active_hosts, result)
            
            if analysis_options.get('web_detection', True):  # Default enabled
                self._detect_web_services(active_hosts, result)
            
            # Additional vulnerability checks
            if analysis_options.get('vulnerability_scan', False):
                self._perform_vulnerability_checks(active_hosts, result)
            
            end_time = datetime.now()
            result.analysis_time = (end_time - start_time).total_seconds()
            
            self._send_progress(f"Analysis completed in {result.analysis_time:.1f} seconds")
            logger.info(f"Security analysis completed: {len(result.vulnerabilities)} issues found")
            
            return result
            
        except Exception as e:
            logger.error(f"Security analysis error: {e}")
            result.analysis_time = (datetime.now() - start_time).total_seconds()
            return result
    
    def _calculate_total_checks(self, hosts: List[Host], options: Dict[str, bool]) -> int:
        """Calculate total number of checks to perform."""
        total = 0
        
        for host in hosts:
            open_ports = [p for p in host.ports if p.state == 'open']
            
            if options.get('tls_check', False):
                # TLS checks for HTTPS and other TLS services
                tls_ports = [p for p in open_ports if self._is_tls_service(p)]
                total += len(tls_ports)
            
            if options.get('ssl_check', False):
                # SSL certificate checks
                ssl_ports = [p for p in open_ports if self._is_ssl_service(p)]
                total += len(ssl_ports)
            
            if options.get('smb_check', False):
                # SMB checks
                smb_ports = [p for p in open_ports if p.number in [139, 445]]
                total += len(smb_ports)
            
            if options.get('web_detection', True):
                # Web service detection
                web_ports = [p for p in open_ports if self._is_potential_web_service(p)]
                total += len(web_ports)
        
        return total
    
    def _analyze_tls_services(self, hosts: List[Host], result: SecurityAnalysisResult):
        """Analyze TLS services for version and configuration issues."""
        self._send_progress("Analyzing TLS services...")
        
        tls_targets = []
        for host in hosts:
            for port in host.ports:
                if port.state == 'open' and self._is_tls_service(port):
                    tls_targets.append((host.ip_address, port.number))
        
        if not tls_targets:
            return
        
        # Analyze TLS services concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self.tls_analyzer.analyze_tls, host, port): (host, port)
                for host, port in tls_targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                if self.cancel_event.is_set():
                    break
                
                host, port = future_to_target[future]
                try:
                    tls_result = future.result(timeout=30)
                    if tls_result:
                        result.tls_results.append({
                            'host': host,
                            'port': port,
                            'result': tls_result
                        })
                        
                        # Check for vulnerabilities
                        self._check_tls_vulnerabilities(host, port, tls_result, result)
                        
                except Exception as e:
                    logger.warning(f"TLS analysis failed for {host}:{port}: {e}")
                
                result.completed_checks += 1
                self._update_progress(result)
    
    def _analyze_ssl_certificates(self, hosts: List[Host], result: SecurityAnalysisResult):
        """Analyze SSL certificates for expiry and configuration issues."""
        self._send_progress("Analyzing SSL certificates...")
        
        ssl_targets = []
        for host in hosts:
            for port in host.ports:
                if port.state == 'open' and self._is_ssl_service(port):
                    ssl_targets.append((host.ip_address, port.number))
        
        if not ssl_targets:
            return
        
        # Analyze SSL certificates concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self.ssl_analyzer.analyze_certificate, host, port): (host, port)
                for host, port in ssl_targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                if self.cancel_event.is_set():
                    break
                
                host, port = future_to_target[future]
                try:
                    ssl_result = future.result(timeout=30)
                    if ssl_result:
                        result.ssl_results.append({
                            'host': host,
                            'port': port,
                            'result': ssl_result
                        })
                        
                        # Check for SSL vulnerabilities
                        self._check_ssl_vulnerabilities(host, port, ssl_result, result)
                        
                except Exception as e:
                    logger.warning(f"SSL analysis failed for {host}:{port}: {e}")
                
                result.completed_checks += 1
                self._update_progress(result)
    
    def _analyze_smb_services(self, hosts: List[Host], result: SecurityAnalysisResult):
        """Analyze SMB services for signing and version issues."""
        self._send_progress("Analyzing SMB services...")
        
        smb_targets = []
        for host in hosts:
            smb_ports = [p for p in host.ports if p.state == 'open' and p.number in [139, 445]]
            if smb_ports:
                smb_targets.append(host.ip_address)
        
        if not smb_targets:
            return
        
        # Analyze SMB services
        for host_ip in smb_targets:
            if self.cancel_event.is_set():
                break
            
            try:
                smb_result = self.smb_analyzer.analyze_smb_signing(host_ip)
                if smb_result:
                    result.smb_results.append({
                        'host': host_ip,
                        'result': smb_result
                    })
                    
                    # Check for SMB vulnerabilities
                    self._check_smb_vulnerabilities(host_ip, smb_result, result)
                    
            except Exception as e:
                logger.warning(f"SMB analysis failed for {host_ip}: {e}")
            
            result.completed_checks += 1
            self._update_progress(result)
    
    def _detect_web_services(self, hosts: List[Host], result: SecurityAnalysisResult):
        """Detect and analyze web services."""
        self._send_progress("Detecting web services...")
        
        web_targets = []
        for host in hosts:
            for port in host.ports:
                if port.state == 'open' and self._is_potential_web_service(port):
                    web_targets.append((host.ip_address, port.number, host.hostname))
        
        if not web_targets:
            return
        
        # Detect web services concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_target = {
                executor.submit(self.web_detector.detect_web_service, host, port, hostname): (host, port)
                for host, port, hostname in web_targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                if self.cancel_event.is_set():
                    break
                
                host, port = future_to_target[future]
                try:
                    web_result = future.result(timeout=15)
                    if web_result and web_result.get('is_web_service', False):
                        result.web_services.append({
                            'host': host,
                            'port': port,
                            'result': web_result
                        })
                        
                except Exception as e:
                    logger.warning(f"Web detection failed for {host}:{port}: {e}")
                
                result.completed_checks += 1
                self._update_progress(result)
    
    def _perform_vulnerability_checks(self, hosts: List[Host], result: SecurityAnalysisResult):
        """Perform additional vulnerability checks."""
        self._send_progress("Performing vulnerability checks...")
        
        # Check for common vulnerable services
        for host in hosts:
            for port in host.ports:
                if port.state == 'open':
                    self._check_common_vulnerabilities(host, port, result)
    
    def _check_tls_vulnerabilities(self, host: str, port: int, tls_result: Dict[str, Any], 
                                 result: SecurityAnalysisResult):
        """Check TLS configuration for vulnerabilities."""
        supported_versions = tls_result.get('supported_versions', [])
        
        # Check for weak TLS versions
        if 'TLSv1.0' in supported_versions:
            result.add_vulnerability(
                host, port, "TLS 1.0 Supported",
                severity="medium",
                details="TLS 1.0 is deprecated and should be disabled"
            )
        
        if 'TLSv1.1' in supported_versions:
            result.add_vulnerability(
                host, port, "TLS 1.1 Supported",
                severity="low",
                details="TLS 1.1 is deprecated and should be disabled"
            )
        
        # Check cipher suites
        weak_ciphers = tls_result.get('weak_ciphers', [])
        if weak_ciphers:
            result.add_vulnerability(
                host, port, "Weak Cipher Suites",
                severity="medium",
                details=f"Weak ciphers detected: {', '.join(weak_ciphers)}"
            )
    
    def _check_ssl_vulnerabilities(self, host: str, port: int, ssl_result: Dict[str, Any], 
                                 result: SecurityAnalysisResult):
        """Check SSL certificate for vulnerabilities."""
        cert_info = ssl_result.get('certificate', {})
        
        # Check certificate expiry
        expiry_date = cert_info.get('expiry_date')
        if expiry_date:
            days_until_expiry = (expiry_date - datetime.now()).days
            if days_until_expiry < 0:
                result.add_vulnerability(
                    host, port, "Expired SSL Certificate",
                    severity="high",
                    details=f"Certificate expired {abs(days_until_expiry)} days ago"
                )
            elif days_until_expiry < 30:
                result.add_vulnerability(
                    host, port, "SSL Certificate Expiring Soon",
                    severity="medium",
                    details=f"Certificate expires in {days_until_expiry} days"
                )
        
        # Check for SSLv3
        if ssl_result.get('sslv3_supported', False):
            result.add_vulnerability(
                host, port, "SSLv3 Supported",
                severity="high",
                details="SSLv3 is vulnerable to POODLE attack"
            )
        
        # Check certificate chain issues
        if ssl_result.get('self_signed', False):
            result.add_vulnerability(
                host, port, "Self-Signed Certificate",
                severity="low",
                details="Certificate is self-signed"
            )
    
    def _check_smb_vulnerabilities(self, host: str, smb_result: Dict[str, Any], 
                                 result: SecurityAnalysisResult):
        """Check SMB configuration for vulnerabilities."""
        if not smb_result.get('signing_required', True):
            result.add_vulnerability(
                host, 445, "SMB Signing Not Required",
                severity="medium",
                details="SMB signing is not enforced, vulnerable to relay attacks"
            )
        
        # Check SMB version
        smb_version = smb_result.get('version')
        if smb_version and '1' in smb_version:
            result.add_vulnerability(
                host, 445, "SMBv1 Enabled",
                severity="high",
                details="SMBv1 is vulnerable and should be disabled"
            )
    
    def _check_common_vulnerabilities(self, host: Host, port, result: SecurityAnalysisResult):
        """Check for common service vulnerabilities."""
        service = port.service.lower() if port.service else ""
        version = port.version.lower() if port.version else ""
        
        # Common vulnerable services
        vulnerable_services = {
            'telnet': ("Telnet Service", "high", "Telnet transmits data in clear text"),
            'ftp': ("FTP Service", "medium", "FTP may transmit credentials in clear text"),
            'rsh': ("RSH Service", "high", "RSH is insecure and deprecated"),
            'rlogin': ("RLogin Service", "high", "RLogin is insecure and deprecated"),
        }
        
        for vuln_service, (vuln_name, severity, details) in vulnerable_services.items():
            if vuln_service in service:
                result.add_vulnerability(
                    host.ip_address, port.number, vuln_name,
                    severity=severity, details=details
                )
    
    def _is_tls_service(self, port) -> bool:
        """Check if port is likely to support TLS."""
        tls_ports = [443, 993, 995, 465, 587, 636, 989, 990, 992, 8443, 9443]
        if port.number in tls_ports:
            return True
        
        if port.service:
            tls_services = ['https', 'imaps', 'pop3s', 'smtps', 'ldaps', 'ftps']
            return any(svc in port.service.lower() for svc in tls_services)
        
        return False
    
    def _is_ssl_service(self, port) -> bool:
        """Check if port is likely to support SSL."""
        return self._is_tls_service(port)  # Same as TLS for our purposes
    
    def _is_potential_web_service(self, port) -> bool:
        """Check if port might be a web service."""
        web_ports = [80, 443, 8000, 8008, 8080, 8443, 8888, 9080, 9443]
        if port.number in web_ports:
            return True
        
        if port.service:
            web_services = ['http', 'https', 'web', 'apache', 'nginx', 'iis']
            return any(svc in port.service.lower() for svc in web_services)
        
        return False
    
    def _send_progress(self, message: str):
        """Send progress update."""
        logger.info(message)
        if self.progress_callback:
            try:
                self.progress_callback(message)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
    
    def _update_progress(self, result: SecurityAnalysisResult):
        """Update progress with completion percentage."""
        if result.total_checks > 0:
            percentage = (result.completed_checks / result.total_checks) * 100
            self._send_progress(f"Analysis progress: {percentage:.1f}% ({result.completed_checks}/{result.total_checks})")
    
    def cancel_analysis(self):
        """Cancel ongoing analysis."""
        self.cancel_event.set()