"""Main security analysis coordinator."""

from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import concurrent.futures
import threading

from .tls_analyzer import TLSAnalyzer
from .ssl_analyzer import SSLAnalyzer
from .smb_analyzer import SMBAnalyzer
from .web_detector import WebDetector
from ..models.scan_result import ScanResult, Host, Port
from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SecurityAnalysisResult:
    """Container for security analysis results."""
    
    def __init__(self):
        self.tls_results: List[Dict[str, Any]] = []
        self.ssl_results: List[Dict[str, Any]] = []
        self.smb_results: List[Dict[str, Any]] = []
        self.web_services: List[Dict[str, Any]] = []
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.analysis_duration: Optional[float] = None
        self.total_checks = 0
        self.completed_checks = 0
        self.lock = threading.Lock()
    
    def add_vulnerability(self, host: str, port: Optional[int], vulnerability: str,
                         severity: str = "medium", details: str = ""):
        """Add a vulnerability finding in a thread-safe way."""
        with self.lock:
            self.vulnerabilities.append({
                'host': host,
                'port': port,
                'vulnerability': vulnerability,
                'severity': severity.lower(),
                'details': details,
                'timestamp': datetime.now()
            })
    
    def get_summary(self) -> Dict[str, Any]:
        """Get analysis summary."""
        with self.lock:
            severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            for vuln in self.vulnerabilities:
                severity = vuln.get('severity', 'medium')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return {
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': severity_counts,
            'tls_checks': len(self.tls_results),
            'ssl_checks': len(self.ssl_results),
            'smb_checks': len(self.smb_results),
            'web_services_found': len(self.web_services),
            'analysis_duration': self.analysis_duration
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
        self.progress_callback: Optional[Callable[[str], None]] = None
    
    def set_progress_callback(self, callback: Optional[Callable[[str], None]]):
        """Set progress callback function."""
        self.progress_callback = callback
    
    def analyze_scan_results(self, scan_result: ScanResult, 
                           analysis_options: Dict[str, bool]) -> SecurityAnalysisResult:
        """Perform comprehensive security analysis on scan results."""
        start_time = datetime.now()
        result = SecurityAnalysisResult()
        self.cancel_event.clear()
        
        active_hosts = [host for host in scan_result.hosts if host.state == 'up']
        if not active_hosts:
            logger.warning("No active hosts found for analysis")
            return result

        tasks = []
        if analysis_options.get('tls_check'):
            tasks.append(self._analyze_tls_services)
        if analysis_options.get('ssl_check'):
            tasks.append(self._analyze_ssl_certificates)
        if analysis_options.get('smb_check'):
            tasks.append(self._analyze_smb_services)
        if analysis_options.get('web_detection'):
            tasks.append(self._detect_web_services)

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks) or 1) as executor:
            future_to_task = {executor.submit(task, active_hosts, result): task for task in tasks}
            concurrent.futures.wait(future_to_task)

        end_time = datetime.now()
        result.analysis_duration = (end_time - start_time).total_seconds()
        
        if self.cancel_event.is_set():
             self._send_progress("Analysis cancelled.")
        else:
             self._send_progress(f"Analysis completed in {result.analysis_duration:.1f} seconds.")

        logger.info(f"Security analysis completed: {len(result.vulnerabilities)} potential issues found.")
        return result

    def _update_progress(self, result: SecurityAnalysisResult, message: str = "Analyzing..."):
        """Update progress with completion percentage."""
        with result.lock:
            result.completed_checks += 1
            if result.total_checks > 0:
                percentage = (result.completed_checks / result.total_checks) * 100
                progress_message = f"{message} {percentage:.0f}% ({result.completed_checks}/{result.total_checks})"
                self._send_progress(progress_message)

    def _analyze_tls_services(self, hosts: List[Host], result: SecurityAnalysisResult):
        self._send_progress("Starting TLS analysis...")
        targets = [(h.ip_address, p.number) for h in hosts for p in h.ports if p.state == 'open' and 'ssl' in (p.service or '') or 'https' in (p.service or '')]
        tls_results = self.tls_analyzer.bulk_analyze(targets, self.max_workers)
        with result.lock:
            result.tls_results = tls_results
        for res in tls_results:
            for vuln in res.get('vulnerabilities', []):
                result.add_vulnerability(res['host'], res['port'], vuln, 'low', f"TLS Protocol issue: {vuln}")
    
    def _analyze_ssl_certificates(self, hosts: List[Host], result: SecurityAnalysisResult):
        self._send_progress("Starting SSL certificate analysis...")
        targets = [(h.ip_address, p.number) for h in hosts for p in h.ports if p.state == 'open' and 'ssl' in (p.service or '') or 'https' in (p.service or '')]
        ssl_results = self.ssl_analyzer.bulk_analyze(targets, self.max_workers)
        with result.lock:
            result.ssl_results = ssl_results
        for res in ssl_results:
            for vuln in res.get('vulnerabilities', []):
                result.add_vulnerability(res['host'], res['port'], vuln, 'medium', f"SSL Certificate issue: {vuln}")

    def _analyze_smb_services(self, hosts: List[Host], result: SecurityAnalysisResult):
        self._send_progress("Starting SMB analysis...")
        targets = list({h.ip_address for h in hosts for p in h.ports if p.number in [139, 445] and p.state == 'open'})
        smb_results = self.smb_analyzer.bulk_analyze(targets, self.max_workers)
        with result.lock:
            result.smb_results = smb_results
        for res in smb_results:
            for vuln in res.get('vulnerabilities', []):
                result.add_vulnerability(res['host'], res['ports_tested'][0] if res['ports_tested'] else 445, vuln, 'high', f"SMB issue: {vuln}")

    def _detect_web_services(self, hosts: List[Host], result: SecurityAnalysisResult):
        self._send_progress("Starting Web service detection...")
        targets = [(h.ip_address, p.number, h.hostname) for h in hosts for p in h.ports if p.state == 'open' and 'http' in (p.service or '')]
        web_services = self.web_detector.bulk_detect(targets, self.max_workers)
        with result.lock:
            result.web_services = web_services
        for res in web_services:
            for vuln in res.get('vulnerabilities', []):
                 result.add_vulnerability(res['host'], res['port'], vuln, 'low', f"Web configuration issue: {vuln}")

    def _send_progress(self, message: str):
        if self.progress_callback and not self.cancel_event.is_set():
            try:
                self.progress_callback(message)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")
    
    def cancel_analysis(self):
        """Cancel ongoing analysis."""
        logger.info("Cancellation signal received for security analysis.")
        self.cancel_event.set()