"""Web service detector and analyzer."""

import requests
import socket
from urllib.parse import urljoin
from typing import Dict, Any, Optional, List
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class WebDetector:
    """Detector for web services and web applications."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = self._create_session()
        
        # Common web paths to check
        self.common_paths = [
            '/',
            '/admin',
            '/login',
            '/api',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/',
            '/status',
            '/health'
        ]
        
        # Web server signatures
        self.server_signatures = {
            'apache': ['Apache', 'apache'],
            'nginx': ['nginx'],
            'iis': ['Microsoft-IIS', 'IIS'],
            'tomcat': ['Apache-Coyote', 'Tomcat'],
            'jetty': ['Jetty'],
            'lighttpd': ['lighttpd'],
            'caddy': ['Caddy']
        }
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry strategy."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'User-Agent': 'ReMap Security Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def detect_web_service(self, host: str, port: int, hostname: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Detect if a service is a web server and gather information.
        
        Returns:
            Dictionary with web service information or None if not a web service
        """
        try:
            result = {
                'host': host,
                'port': port,
                'hostname': hostname,
                'is_web_service': False,
                'protocols': [],
                'server_info': {},
                'applications': [],
                'security_headers': {},
                'vulnerabilities': [],
                'urls': []
            }
            
            # Determine protocols to test
            protocols = self._determine_protocols(port)
            
            for protocol in protocols:
                try:
                    protocol_result = self._test_protocol(host, port, protocol, hostname)
                    if protocol_result and protocol_result.get('is_web_service', False):
                        result['is_web_service'] = True
                        result['protocols'].append(protocol)
                        
                        # Merge results
                        if protocol_result.get('server_info'):
                            result['server_info'].update(protocol_result['server_info'])
                        
                        if protocol_result.get('applications'):
                            result['applications'].extend(protocol_result['applications'])
                        
                        if protocol_result.get('security_headers'):
                            result['security_headers'].update(protocol_result['security_headers'])
                        
                        if protocol_result.get('urls'):
                            result['urls'].extend(protocol_result['urls'])
                        
                except Exception as e:
                    logger.debug(f"Protocol test failed for {protocol}://{host}:{port}: {e}")
            
            if result['is_web_service']:
                # Analyze for vulnerabilities
                result['vulnerabilities'] = self._check_web_vulnerabilities(result)
                
                return result
            
        except Exception as e:
            logger.error(f"Web detection failed for {host}:{port}: {e}")
        
        return None
    
    def _determine_protocols(self, port: int) -> List[str]:
        """Determine which protocols to test based on port number."""
        # HTTPS ports
        if port in [443, 8443, 9443]:
            return ['https', 'http']
        
        # HTTP ports
        elif port in [80, 8080, 8000, 8008, 8888, 9080]:
            return ['http', 'https']
        
        # Try both for unknown ports
        else:
            return ['http', 'https']
    
    def _test_protocol(self, host: str, port: int, protocol: str, hostname: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Test a specific protocol on the host:port."""
        try:
            # Build URL
            target_host = hostname if hostname else host
            base_url = f"{protocol}://{target_host}:{port}"
            
            # Test root path first
            response = self.session.get(
                base_url,
                timeout=self.timeout,
                verify=False,  # Ignore SSL certificate errors
                allow_redirects=True
            )
            
            if not self._is_web_response(response):
                return None
            
            result = {
                'is_web_service': True,
                'server_info': self._extract_server_info(response),
                'applications': self._detect_applications(response),
                'security_headers': self._analyze_security_headers(response.headers),
                'urls': [base_url]
            }
            
            # Test additional paths
            additional_urls = self._test_common_paths(base_url)
            result['urls'].extend(additional_urls)
            
            return result
            
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {protocol}://{host}:{port}: {e}")
        except Exception as e:
            logger.debug(f"Protocol test error for {protocol}://{host}:{port}: {e}")
        
        return None
    
    def _is_web_response(self, response: requests.Response) -> bool:
        """Check if response indicates a web service."""
        # Check status code
        if response.status_code >= 400 and response.status_code != 401 and response.status_code != 403:
            return False
        
        # Check content type
        content_type = response.headers.get('content-type', '').lower()
        web_content_types = [
            'text/html', 'text/plain', 'application/json', 'application/xml',
            'text/xml', 'application/javascript', 'text/css'
        ]
        
        if any(ct in content_type for ct in web_content_types):
            return True
        
        # Check for web server headers
        server_header = response.headers.get('server', '').lower()
        if any(sig in server_header for signatures in self.server_signatures.values() 
               for sig in [s.lower() for s in signatures]):
            return True
        
        # Check for other web-specific headers
        web_headers = ['x-powered-by', 'x-aspnet-version', 'x-frame-options', 'x-content-type-options']
        if any(header in response.headers for header in web_headers):
            return True
        
        return False
    
    def _extract_server_info(self, response: requests.Response) -> Dict[str, Any]:
        """Extract web server information from response."""
        info = {}
        
        # Server header
        server = response.headers.get('server', '')
        if server:
            info['server'] = server
            
            # Identify server type
            for server_type, signatures in self.server_signatures.items():
                if any(sig.lower() in server.lower() for sig in signatures):
                    info['server_type'] = server_type
                    break
        
        # Technology headers
        powered_by = response.headers.get('x-powered-by', '')
        if powered_by:
            info['powered_by'] = powered_by
        
        aspnet_version = response.headers.get('x-aspnet-version', '')
        if aspnet_version:
            info['aspnet_version'] = aspnet_version
        
        # Additional server info
        info['status_code'] = response.status_code
        info['content_length'] = response.headers.get('content-length', 0)
        info['content_type'] = response.headers.get('content-type', '')
        
        return info
    
    def _detect_applications(self, response: requests.Response) -> List[Dict[str, Any]]:
        """Detect web applications from response."""
        applications = []
        
        try:
            content = response.text.lower()
            headers = response.headers
            
            # Common CMS/Framework detection
            detections = {
                'wordpress': [
                    'wp-content/', 'wp-includes/', 'wordpress',
                    '/wp-admin/', 'wp-json'
                ],
                'drupal': [
                    'drupal', '/sites/default/', 'drupal.js',
                    '/modules/', '/themes/'
                ],
                'joomla': [
                    'joomla', '/administrator/', 'joomla.js',
                    '/components/', '/modules/'
                ],
                'sharepoint': [
                    'sharepoint', '_layouts/', 'spthemes',
                    'microsoft sharepoint'
                ],
                'apache_tomcat': [
                    'apache tomcat', 'tomcat', '/manager/html'
                ],
                'phpmyadmin': [
                    'phpmyadmin', 'pma_', 'phpMyAdmin'
                ],
                'jenkins': [
                    'jenkins', 'hudson', '/jenkins/'
                ],
                'gitlab': [
                    'gitlab', '/gitlab/', 'gitlab-'
                ],
                'confluence': [
                    'confluence', 'atlassian', '/confluence/'
                ],
                'mediawiki': [
                    'mediawiki', 'wiki', '/mediawiki/'
                ]
            }
            
            for app_name, signatures in detections.items():
                if any(sig in content for sig in signatures):
                    applications.append({
                        'name': app_name.replace('_', ' ').title(),
                        'confidence': 'high',
                        'evidence': [sig for sig in signatures if sig in content][:3]
                    })
            
            # Check for common JavaScript frameworks
            js_frameworks = {
                'jquery': ['jquery', '$'],
                'angular': ['angular', 'ng-'],
                'react': ['react', 'reactdom'],
                'vue': ['vue.js', 'vue'],
                'bootstrap': ['bootstrap', 'btn-']
            }
            
            for framework, signatures in js_frameworks.items():
                if any(sig in content for sig in signatures):
                    applications.append({
                        'name': framework.title(),
                        'type': 'javascript_framework',
                        'confidence': 'medium'
                    })
            
        except Exception as e:
            logger.debug(f"Error detecting applications: {e}")
        
        return applications
    
    def _analyze_security_headers(self, headers) -> Dict[str, Any]:
        """Analyze security headers."""
        security_headers = {}
        
        # Important security headers to check
        header_checks = {
            'x-frame-options': 'X-Frame-Options',
            'x-content-type-options': 'X-Content-Type-Options',
            'x-xss-protection': 'X-XSS-Protection',
            'strict-transport-security': 'Strict-Transport-Security',
            'content-security-policy': 'Content-Security-Policy',
            'referrer-policy': 'Referrer-Policy',
            'permissions-policy': 'Permissions-Policy',
            'x-permitted-cross-domain-policies': 'X-Permitted-Cross-Domain-Policies'
        }
        
        for header_key, header_name in header_checks.items():
            header_value = headers.get(header_key) or headers.get(header_name.lower())
            if header_value:
                security_headers[header_name] = {
                    'present': True,
                    'value': header_value
                }
            else:
                security_headers[header_name] = {
                    'present': False,
                    'value': None
                }
        
        return security_headers
    
    def _test_common_paths(self, base_url: str) -> List[str]:
        """Test common paths and return accessible URLs."""
        accessible_urls = []
        
        for path in self.common_paths:
            try:
                url = urljoin(base_url, path)
                response = self.session.head(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )
                
                # Consider accessible if not 404
                if response.status_code != 404:
                    accessible_urls.append(url)
                    
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                logger.debug(f"Error testing path {path}: {e}")
        
        return accessible_urls
    
    def _check_web_vulnerabilities(self, web_result: Dict[str, Any]) -> List[str]:
        """Check for web application vulnerabilities."""
        vulnerabilities = []
        
        # Check security headers
        security_headers = web_result.get('security_headers', {})
        
        missing_headers = []
        for header_name, header_info in security_headers.items():
            if not header_info.get('present', False):
                missing_headers.append(header_name)
        
        if missing_headers:
            vulnerabilities.append(f"Missing security headers: {', '.join(missing_headers[:3])}")
        
        # Check for insecure configurations
        server_info = web_result.get('server_info', {})
        
        # Check for server version disclosure
        server = server_info.get('server', '')
        if server and any(char.isdigit() for char in server):
            vulnerabilities.append("Server version disclosed in headers")
        
        # Check for development/test applications
        applications = web_result.get('applications', [])
        risky_apps = ['phpmyadmin', 'jenkins', 'tomcat']
        
        for app in applications:
            app_name = app.get('name', '').lower()
            if any(risky in app_name for risky in risky_apps):
                vulnerabilities.append(f"Potentially risky application exposed: {app.get('name')}")
        
        # Check URLs for sensitive paths
        urls = web_result.get('urls', [])
        sensitive_paths = ['/admin', '/login', '/api', '/.well-known/']
        
        for url in urls:
            if any(path in url for path in sensitive_paths):
                vulnerabilities.append(f"Sensitive path accessible: {url}")
                break
        
        return vulnerabilities
    
    def bulk_detect(self, targets: List[tuple], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Detect web services on multiple targets concurrently."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.detect_web_service, host, port, hostname): (host, port)
                for host, port, hostname in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                host, port = future_to_target[future]
                try:
                    result = future.result(timeout=30)
                    if result and result.get('is_web_service', False):
                        results.append(result)
                except Exception as e:
                    logger.error(f"Web detection failed for {host}:{port}: {e}")
        
        return results
    
    def get_web_urls_from_scan_result(self, scan_result) -> List[Dict[str, str]]:
        """Extract potential web URLs from scan results."""
        web_urls = []
        
        for host in scan_result.hosts:
            if host.state != 'up':
                continue
            
            for port in host.ports:
                if port.state != 'open':
                    continue
                
                # Determine likely protocol
                protocol = 'https' if port.number in [443, 8443, 9443] else 'http'
                
                # Check if it might be a web service
                if self._is_likely_web_port(port):
                    url = f"{protocol}://{host.hostname or host.ip_address}:{port.number}"
                    web_urls.append({
                        'host': host.ip_address,
                        'hostname': host.hostname,
                        'port': port.number,
                        'service': port.service,
                        'url': url,
                        'protocol': protocol
                    })
        
        return web_urls
    
    def _is_likely_web_port(self, port) -> bool:
        """Check if a port is likely to be a web service."""
        # Common web ports
        web_ports = [80, 443, 8000, 8008, 8080, 8443, 8888, 9080, 9443, 3000, 5000, 9000]
        if port.number in web_ports:
            return True
        
        # Check service name
        if port.service:
            web_services = ['http', 'https', 'web', 'apache', 'nginx', 'iis', 'tomcat']
            return any(svc in port.service.lower() for svc in web_services)
        
        # Check for SSL/TLS indicators
        if port.extra_info:
            scripts = port.extra_info.get('scripts', [])
            for script in scripts:
                script_id = script.get('id', '').lower()
                if any(indicator in script_id for indicator in ['http', 'ssl', 'tls']):
                    return True
        
        return False