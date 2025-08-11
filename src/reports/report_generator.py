"""Report generator for scan and analysis results."""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom

from ..models.scan_result import ScanResult
from ..analysis.security_analyzer import SecurityAnalysisResult
from ..utils.logger import setup_logger
from ..utils.file_handler import FileHandler

logger = setup_logger(__name__)

class ReportGenerator:
    """Generate reports in various formats."""
    
    def __init__(self):
        self.supported_formats = ['json', 'csv', 'html', 'xml', 'txt']
    
    def generate_report(self, scan_result: ScanResult, 
                       analysis_result: Optional[SecurityAnalysisResult] = None,
                       report_format: str = 'html',
                       output_path: str = None) -> str:
        """
        Generate comprehensive report.
        
        Args:
            scan_result: Nmap scan results
            analysis_result: Security analysis results
            report_format: Output format (json, csv, html, xml, txt)
            output_path: Output file path (auto-generated if None)
        
        Returns:
            Path to generated report file
        """
        try:
            if report_format.lower() not in self.supported_formats:
                raise ValueError(f"Unsupported format: {report_format}")
            
            # Generate output path if not provided
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"remap_report_{timestamp}.{report_format.lower()}"
                output_path = str(Path.home() / ".remap" / "reports" / filename)
            
            # Ensure output directory exists
            FileHandler.ensure_directory_exists(str(Path(output_path).parent))
            
            # Generate report based on format
            if report_format.lower() == 'json':
                return self._generate_json_report(scan_result, analysis_result, output_path)
            elif report_format.lower() == 'csv':
                return self._generate_csv_report(scan_result, analysis_result, output_path)
            elif report_format.lower() == 'html':
                return self._generate_html_report(scan_result, analysis_result, output_path)
            elif report_format.lower() == 'xml':
                return self._generate_xml_report(scan_result, analysis_result, output_path)
            elif report_format.lower() == 'txt':
                return self._generate_text_report(scan_result, analysis_result, output_path)
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            raise
    
    def _generate_json_report(self, scan_result: ScanResult, 
                            analysis_result: Optional[SecurityAnalysisResult],
                            output_path: str) -> str:
        """Generate JSON report."""
        try:
            report_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'generator': 'ReMap Security Scanner',
                    'version': '1.0'
                },
                'scan_info': scan_result.scan_info,
                'summary': {
                    'total_hosts': scan_result.total_hosts,
                    'hosts_up': scan_result.hosts_up,
                    'scan_duration': scan_result.duration
                },
                'hosts': []
            }
            
            # Add host data
            for host in scan_result.hosts:
                host_data = {
                    'ip_address': host.ip_address,
                    'hostname': host.hostname,
                    'state': host.state,
                    'os_info': host.os_info,
                    'ports': []
                }
                
                for port in host.ports:
                    port_data = {
                        'number': port.number,
                        'protocol': port.protocol,
                        'state': port.state,
                        'service': port.service,
                        'version': port.version,
                        'extra_info': port.extra_info
                    }
                    host_data['ports'].append(port_data)
                
                host_data['extra_info'] = host.extra_info
                report_data['hosts'].append(host_data)
            
            # Add analysis results if available
            if analysis_result:
                report_data['security_analysis'] = {
                    'summary': analysis_result.get_summary(),
                    'vulnerabilities': analysis_result.vulnerabilities,
                    'tls_results': analysis_result.tls_results,
                    'ssl_results': analysis_result.ssl_results,
                    'smb_results': analysis_result.smb_results,
                    'web_services': analysis_result.web_services
                }
            
            # Write JSON report
            if FileHandler.write_json_file(output_path, report_data):
                logger.info(f"JSON report generated: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write JSON report")
                
        except Exception as e:
            logger.error(f"JSON report generation failed: {e}")
            raise
    
    def _generate_csv_report(self, scan_result: ScanResult, 
                           analysis_result: Optional[SecurityAnalysisResult],
                           output_path: str) -> str:
        """Generate CSV report."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'IP Address', 'Hostname', 'Host State', 'Port', 'Protocol', 
                    'Port State', 'Service', 'Version', 'OS Info', 'Vulnerabilities'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for host in scan_result.hosts:
                    if not host.ports:
                        # Host without ports
                        vulnerabilities = []
                        if analysis_result:
                            host_vulns = [v for v in analysis_result.vulnerabilities 
                                        if v['host'] == host.ip_address]
                            vulnerabilities = [v['vulnerability'] for v in host_vulns]
                        
                        writer.writerow({
                            'IP Address': host.ip_address,
                            'Hostname': host.hostname or '',
                            'Host State': host.state,
                            'Port': '',
                            'Protocol': '',
                            'Port State': '',
                            'Service': '',
                            'Version': '',
                            'OS Info': host.os_info or '',
                            'Vulnerabilities': '; '.join(vulnerabilities)
                        })
                    else:
                        for port in host.ports:
                            # Find vulnerabilities for this host/port
                            vulnerabilities = []
                            if analysis_result:
                                port_vulns = [v for v in analysis_result.vulnerabilities 
                                            if v['host'] == host.ip_address and 
                                            v.get('port') == port.number]
                                vulnerabilities = [v['vulnerability'] for v in port_vulns]
                            
                            writer.writerow({
                                'IP Address': host.ip_address,
                                'Hostname': host.hostname or '',
                                'Host State': host.state,
                                'Port': port.number,
                                'Protocol': port.protocol,
                                'Port State': port.state,
                                'Service': port.service or '',
                                'Version': port.version or '',
                                'OS Info': host.os_info or '',
                                'Vulnerabilities': '; '.join(vulnerabilities)
                            })
            
            logger.info(f"CSV report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"CSV report generation failed: {e}")
            raise
    
    def _generate_html_report(self, scan_result: ScanResult, 
                            analysis_result: Optional[SecurityAnalysisResult],
                            output_path: str) -> str:
        """Generate HTML report."""
        try:
            html_content = self._build_html_report(scan_result, analysis_result)
            
            if FileHandler.write_text_file(output_path, html_content):
                logger.info(f"HTML report generated: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write HTML report")
                
        except Exception as e:
            logger.error(f"HTML report generation failed: {e}")
            raise
    
    def _build_html_report(self, scan_result: ScanResult, 
                          analysis_result: Optional[SecurityAnalysisResult]) -> str:
        """Build HTML report content."""
        
        # Calculate statistics
        open_ports = sum(len([p for p in host.ports if p.state == 'open']) 
                        for host in scan_result.hosts)
        
        service_counts = {}
        for host in scan_result.hosts:
            for port in host.ports:
                if port.state == 'open' and port.service:
                    service = port.service
                    service_counts[service] = service_counts.get(service, 0) + 1
        
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Vulnerability statistics
        vuln_stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        total_vulnerabilities = 0
        
        if analysis_result:
            for vuln in analysis_result.vulnerabilities:
                severity = vuln.get('severity', 'medium').lower()
                if severity in vuln_stats:
                    vuln_stats[severity] += 1
                total_vulnerabilities += 1
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReMap Security Scan Report</title>
    <style>
        {self._get_html_css()}
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <h1>ReMap Security Scan Report</h1>
            <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <section class="summary">
            <h2>Scan Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>{scan_result.total_hosts}</h3>
                    <p>Total Hosts</p>
                </div>
                <div class="stat-card">
                    <h3>{scan_result.hosts_up}</h3>
                    <p>Hosts Up</p>
                </div>
                <div class="stat-card">
                    <h3>{open_ports}</h3>
                    <p>Open Ports</p>
                </div>
                <div class="stat-card">
                    <h3>{total_vulnerabilities}</h3>
                    <p>Vulnerabilities</p>
                </div>
            </div>
            
            {self._build_vulnerability_summary_html(vuln_stats) if analysis_result else ''}
        </section>
        
        <section class="services">
            <h2>Top Services</h2>
            {self._build_services_table_html(top_services)}
        </section>
        
        {self._build_vulnerabilities_section_html(analysis_result) if analysis_result else ''}
        
        <section class="hosts">
            <h2>Host Details</h2>
            {self._build_hosts_table_html(scan_result.hosts, analysis_result)}
        </section>
        
        {self._build_web_services_section_html(analysis_result) if analysis_result else ''}
        
        <footer class="footer">
            <p>Generated by ReMap Security Scanner v1.0</p>
        </footer>
    </div>
</body>
</html>
"""
        return html_template
    
    def _get_html_css(self) -> str:
        """Get CSS styles for HTML report."""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }
        
        .timestamp {
            font-size: 1.1rem;
            opacity: 0.9;
        }
        
        section {
            background: white;
            margin-bottom: 2rem;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h2 {
            color: #333;
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
            border-bottom: 2px solid #667eea;
            padding-bottom: 0.5rem;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }
        
        .stat-card {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            text-align: center;
            border-left: 4px solid #667eea;
        }
        
        .stat-card h3 {
            font-size: 2rem;
            color: #667eea;
            margin-bottom: 0.5rem;
        }
        
        .vulnerability-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }
        
        .vuln-card {
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        
        .vuln-critical { background-color: #dc3545; }
        .vuln-high { background-color: #fd7e14; }
        .vuln-medium { background-color: #ffc107; color: #333; }
        .vuln-low { background-color: #28a745; }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #667eea;
            color: white;
            font-weight: 600;
        }
        
        tr:hover {
            background-color: #f5f5f5;
        }
        
        .status-up { color: #28a745; font-weight: bold; }
        .status-down { color: #dc3545; font-weight: bold; }
        .status-open { color: #28a745; }
        .status-closed { color: #dc3545; }
        .status-filtered { color: #ffc107; }
        
        .vulnerability {
            margin-bottom: 1rem;
            padding: 1rem;
            border-radius: 5px;
            border-left: 4px solid;
        }
        
        .vulnerability.critical { border-color: #dc3545; background-color: #f8d7da; }
        .vulnerability.high { border-color: #fd7e14; background-color: #fff3cd; }
        .vulnerability.medium { border-color: #ffc107; background-color: #fff3cd; }
        .vulnerability.low { border-color: #28a745; background-color: #d4edda; }
        
        .web-url {
            color: #667eea;
            text-decoration: none;
        }
        
        .web-url:hover {
            text-decoration: underline;
        }
        
        .footer {
            text-align: center;
            padding: 2rem;
            color: #666;
            font-size: 0.9rem;
        }
        """
    
    def _build_vulnerability_summary_html(self, vuln_stats: Dict[str, int]) -> str:
        """Build vulnerability summary HTML."""
        return f"""
        <div class="vulnerability-summary">
            <div class="vuln-card vuln-critical">
                <h3>{vuln_stats['critical']}</h3>
                <p>Critical</p>
            </div>
            <div class="vuln-card vuln-high">
                <h3>{vuln_stats['high']}</h3>
                <p>High</p>
            </div>
            <div class="vuln-card vuln-medium">
                <h3>{vuln_stats['medium']}</h3>
                <p>Medium</p>
            </div>
            <div class="vuln-card vuln-low">
                <h3>{vuln_stats['low']}</h3>
                <p>Low</p>
            </div>
        </div>
        """
    
    def _build_services_table_html(self, top_services: List[tuple]) -> str:
        """Build services table HTML."""
        if not top_services:
            return "<p>No services detected.</p>"
        
        rows = ""
        for service, count in top_services:
            rows += f"<tr><td>{service}</td><td>{count}</td></tr>"
        
        return f"""
        <table>
            <thead>
                <tr>
                    <th>Service</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """
    
    def _build_vulnerabilities_section_html(self, analysis_result: SecurityAnalysisResult) -> str:
        """Build vulnerabilities section HTML."""
        if not analysis_result.vulnerabilities:
            return ""
        
        vuln_html = ""
        for vuln in analysis_result.vulnerabilities:
            severity = vuln.get('severity', 'medium').lower()
            vuln_html += f"""
            <div class="vulnerability {severity}">
                <h4>{vuln['vulnerability']}</h4>
                <p><strong>Host:</strong> {vuln['host']}</p>
                <p><strong>Port:</strong> {vuln.get('port', 'N/A')}</p>
                <p><strong>Severity:</strong> {vuln.get('severity', 'Medium').title()}</p>
                <p><strong>Details:</strong> {vuln.get('details', 'No additional details')}</p>
            </div>
            """
        
        return f"""
        <section class="vulnerabilities">
            <h2>Security Vulnerabilities</h2>
            {vuln_html}
        </section>
        """
    
    def _build_hosts_table_html(self, hosts: List, analysis_result: Optional[SecurityAnalysisResult]) -> str:
        """Build hosts table HTML."""
        rows = ""
        
        for host in hosts:
            # Get host vulnerabilities
            host_vulns = []
            if analysis_result:
                host_vulns = [v for v in analysis_result.vulnerabilities 
                             if v['host'] == host.ip_address]
            
            if not host.ports:
                # Host without ports
                vuln_text = "; ".join([v['vulnerability'] for v in host_vulns]) or "None"
                rows += f"""
                <tr>
                    <td>{host.ip_address}</td>
                    <td>{host.hostname or '-'}</td>
                    <td class="status-{'up' if host.state == 'up' else 'down'}">{host.state.title()}</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>-</td>
                    <td>{vuln_text}</td>
                </tr>
                """
            else:
                for port in host.ports:
                    # Get port-specific vulnerabilities
                    port_vulns = [v for v in host_vulns if v.get('port') == port.number]
                    vuln_text = "; ".join([v['vulnerability'] for v in port_vulns]) or "None"
                    
                    rows += f"""
                    <tr>
                        <td>{host.ip_address}</td>
                        <td>{host.hostname or '-'}</td>
                        <td class="status-{'up' if host.state == 'up' else 'down'}">{host.state.title()}</td>
                        <td>{port.number}</td>
                        <td class="status-{port.state}">{port.state.title()}</td>
                        <td>{port.service or '-'}</td>
                        <td>{port.version or '-'}</td>
                        <td>{vuln_text}</td>
                    </tr>
                    """
        
        return f"""
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Host Status</th>
                    <th>Port</th>
                    <th>Port Status</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Vulnerabilities</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
        """
    
    def _build_web_services_section_html(self, analysis_result: SecurityAnalysisResult) -> str:
        """Build web services section HTML."""
        if not analysis_result.web_services:
            return ""
        
        rows = ""
        for web_service in analysis_result.web_services:
            result = web_service.get('result', {})
            urls = result.get('urls', [])
            main_url = urls[0] if urls else f"http://{web_service['host']}:{web_service['port']}"
            
            applications = result.get('applications', [])
            app_names = [app.get('name', '') for app in applications]
            
            rows += f"""
            <tr>
                <td>{web_service['host']}</td>
                <td>{web_service['port']}</td>
                <td><a href="{main_url}" target="_blank" class="web-url">{main_url}</a></td>
                <td>{', '.join(app_names) or 'Unknown'}</td>
                <td>{result.get('server_info', {}).get('server', 'Unknown')}</td>
            </tr>
            """
        
        return f"""
        <section class="web-services">
            <h2>Web Services Detected</h2>
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>Port</th>
                        <th>URL</th>
                        <th>Applications</th>
                        <th>Server</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </section>
        """
    
    def _generate_xml_report(self, scan_result: ScanResult, 
                           analysis_result: Optional[SecurityAnalysisResult],
                           output_path: str) -> str:
        """Generate XML report."""
        try:
            root = ET.Element("remap_report")
            root.set("generated_at", datetime.now().isoformat())
            root.set("version", "1.0")
            
            # Metadata
            metadata = ET.SubElement(root, "metadata")
            ET.SubElement(metadata, "generator").text = "ReMap Security Scanner"
            ET.SubElement(metadata, "scan_duration").text = str(scan_result.duration)
            ET.SubElement(metadata, "total_hosts").text = str(scan_result.total_hosts)
            ET.SubElement(metadata, "hosts_up").text = str(scan_result.hosts_up)
            
            # Hosts
            hosts_elem = ET.SubElement(root, "hosts")
            for host in scan_result.hosts:
                host_elem = ET.SubElement(hosts_elem, "host")
                host_elem.set("ip", host.ip_address)
                host_elem.set("state", host.state)
                
                if host.hostname:
                    host_elem.set("hostname", host.hostname)
                
                if host.os_info:
                    ET.SubElement(host_elem, "os").text = host.os_info
                
                # Ports
                if host.ports:
                    ports_elem = ET.SubElement(host_elem, "ports")
                    for port in host.ports:
                        port_elem = ET.SubElement(ports_elem, "port")
                        port_elem.set("number", str(port.number))
                        port_elem.set("protocol", port.protocol)
                        port_elem.set("state", port.state)
                        
                        if port.service:
                            port_elem.set("service", port.service)
                        
                        if port.version:
                            port_elem.set("version", port.version)
            
            # Analysis results
            if analysis_result:
                analysis_elem = ET.SubElement(root, "security_analysis")
                
                # Vulnerabilities
                if analysis_result.vulnerabilities:
                    vulns_elem = ET.SubElement(analysis_elem, "vulnerabilities")
                    for vuln in analysis_result.vulnerabilities:
                        vuln_elem = ET.SubElement(vulns_elem, "vulnerability")
                        vuln_elem.set("host", vuln['host'])
                        vuln_elem.set("severity", vuln.get('severity', 'medium'))
                        
                        if vuln.get('port'):
                            vuln_elem.set("port", str(vuln['port']))
                        
                        ET.SubElement(vuln_elem, "title").text = vuln['vulnerability']
                        ET.SubElement(vuln_elem, "details").text = vuln.get('details', '')
                
                # Web services
                if analysis_result.web_services:
                    web_elem = ET.SubElement(analysis_elem, "web_services")
                    for web_service in analysis_result.web_services:
                        service_elem = ET.SubElement(web_elem, "service")
                        service_elem.set("host", web_service['host'])
                        service_elem.set("port", str(web_service['port']))
                        
                        result = web_service.get('result', {})
                        urls = result.get('urls', [])
                        if urls:
                            ET.SubElement(service_elem, "url").text = urls[0]
            
            # Write XML file
            xml_str = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
            if FileHandler.write_text_file(output_path, xml_str):
                logger.info(f"XML report generated: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write XML report")
                
        except Exception as e:
            logger.error(f"XML report generation failed: {e}")
            raise
    
    def _generate_text_report(self, scan_result: ScanResult, 
                            analysis_result: Optional[SecurityAnalysisResult],
                            output_path: str) -> str:
        """Generate text report."""
        try:
            lines = []
            lines.append("=" * 60)
            lines.append("ReMap Security Scan Report")
            lines.append("=" * 60)
            lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")
            
            # Summary
            lines.append("SCAN SUMMARY")
            lines.append("-" * 40)
            lines.append(f"Total Hosts: {scan_result.total_hosts}")
            lines.append(f"Hosts Up: {scan_result.hosts_up}")
            lines.append(f"Scan Duration: {scan_result.duration:.1f}s" if scan_result.duration else "Duration: Unknown")
            lines.append("")
            
            # Vulnerabilities summary
            if analysis_result and analysis_result.vulnerabilities:
                vuln_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
                for vuln in analysis_result.vulnerabilities:
                    severity = vuln.get('severity', 'medium').lower()
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
                
                lines.append("VULNERABILITY SUMMARY")
                lines.append("-" * 40)
                lines.append(f"Critical: {vuln_counts['critical']}")
                lines.append(f"High: {vuln_counts['high']}")
                lines.append(f"Medium: {vuln_counts['medium']}")
                lines.append(f"Low: {vuln_counts['low']}")
                lines.append("")
            
            # Host details
            lines.append("HOST DETAILS")
            lines.append("-" * 40)
            
            for host in scan_result.hosts:
                lines.append(f"Host: {host.ip_address}")
                if host.hostname:
                    lines.append(f"  Hostname: {host.hostname}")
                lines.append(f"  State: {host.state}")
                
                if host.os_info:
                    lines.append(f"  OS: {host.os_info}")
                
                if host.ports:
                    lines.append("  Ports:")
                    for port in host.ports:
                        port_line = f"    {port.number}/{port.protocol} ({port.state})"
                        if port.service:
                            port_line += f" - {port.service}"
                        if port.version:
                            port_line += f" ({port.version})"
                        lines.append(port_line)
                
                # Host vulnerabilities
                if analysis_result:
                    host_vulns = [v for v in analysis_result.vulnerabilities 
                                 if v['host'] == host.ip_address]
                    if host_vulns:
                        lines.append("  Vulnerabilities:")
                        for vuln in host_vulns:
                            lines.append(f"    - {vuln['vulnerability']} [{vuln.get('severity', 'medium').upper()}]")
                            if vuln.get('details'):
                                lines.append(f"      {vuln['details']}")
                
                lines.append("")
            
            # Web services
            if analysis_result and analysis_result.web_services:
                lines.append("WEB SERVICES")
                lines.append("-" * 40)
                
                for web_service in analysis_result.web_services:
                    result = web_service.get('result', {})
                    urls = result.get('urls', [])
                    main_url = urls[0] if urls else f"http://{web_service['host']}:{web_service['port']}"
                    
                    lines.append(f"Host: {web_service['host']}:{web_service['port']}")
                    lines.append(f"  URL: {main_url}")
                    
                    server_info = result.get('server_info', {})
                    if server_info.get('server'):
                        lines.append(f"  Server: {server_info['server']}")
                    
                    applications = result.get('applications', [])
                    if applications:
                        app_names = [app.get('name', '') for app in applications if app.get('name')]
                        if app_names:
                            lines.append(f"  Applications: {', '.join(app_names)}")
                    
                    lines.append("")
            
            # Write text file
            content = "\n".join(lines)
            if FileHandler.write_text_file(output_path, content):
                logger.info(f"Text report generated: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write text report")
                
        except Exception as e:
            logger.error(f"Text report generation failed: {e}")
            raise