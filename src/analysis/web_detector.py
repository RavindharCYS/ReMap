"""Web service detector and analyzer."""

import requests
from typing import Dict, Any, Optional, List
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning

from ..utils.logger import setup_logger

# Suppress only the single InsecureRequestWarning from urllib3 needed for this file.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logger = setup_logger(__name__)

class WebDetector:
    """Detector for web services and web applications."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        
    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy for each call to ensure freshness."""
        session = requests.Session()
        retry_strategy = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({'User-Agent': 'ReMap Security Scanner/1.0'})
        return session

    def detect_web_service(self, host: str, port: int, hostname: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Detect if a service is a web server and gather information."""
        result: Dict[str, Any] = {'host': host, 'port': port, 'is_web_service': False, 'urls': []}
        protocols = ['https' if port in [443, 8443] else 'http', 'https' if port not in [443, 8443] else 'http']
        
        session = self._create_session()
        target_host = hostname if hostname else host

        for protocol in protocols:
            base_url = f"{protocol}://{target_host}:{port}"
            try:
                response = session.get(base_url, timeout=self.timeout, verify=False, allow_redirects=True)
                
                if self._is_web_response(response):
                    result['is_web_service'] = True
                    result['urls'].append(response.url)
                    result['server_info'] = self._extract_server_info(response)
                    result['vulnerabilities'] = self._check_web_vulnerabilities(response)
                    return result
            except requests.exceptions.RequestException:
                continue # Try next protocol
            except Exception as e:
                logger.debug(f"Web detection error for {base_url}: {e}")
        
        return result if result['is_web_service'] else None

    def _is_web_response(self, response: requests.Response) -> bool:
        """Heuristically check if response indicates a web service."""
        if response.status_code >= 500: return False # Server errors don't confirm
        content_type = response.headers.get('content-type', '').lower()
        return any(ct in content_type for ct in ['html', 'json', 'xml', 'javascript', 'text']) or 'server' in response.headers

    def _extract_server_info(self, response: requests.Response) -> Dict[str, Any]:
        """Extract web server information from response."""
        return {
            'server': response.headers.get('server', 'Unknown'),
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type', 'Unknown'),
            'powered_by': response.headers.get('x-powered-by'),
        }

    def _check_web_vulnerabilities(self, response: requests.Response) -> List[str]:
        """Check for basic web application vulnerabilities."""
        vulnerabilities = []
        headers = response.headers
        
        # Check for missing common security headers
        missing_headers = [
            header for header in ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
            if header not in headers
        ]
        if missing_headers:
            vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers)}")

        # Check for server version disclosure
        server = headers.get('server', '')
        if server and any(char.isdigit() for char in server):
            vulnerabilities.append("Server version disclosed in headers")
            
        return vulnerabilities

    def bulk_detect(self, targets: List[tuple], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Detect web services on multiple targets concurrently."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(self.detect_web_service, h, p, hn): (h,p) for h, p, hn in targets}
            for future in concurrent.futures.as_completed(future_to_target):
                result = future.result()
                if result:
                    results.append(result)
        return results