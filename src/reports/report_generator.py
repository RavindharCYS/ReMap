"""Report generator for scan and analysis results."""

import json
import csv
from datetime import datetime
from typing import Dict, Any, List, Optional
from xml.dom import minidom
import xml.etree.ElementTree as ET

from ..models.scan_result import ScanResult
from ..analysis.security_analyzer import SecurityAnalysisResult
from ..utils.logger import setup_logger
from ..utils.file_handler import FileHandler

logger = setup_logger(__name__)

class ReportGenerator:
    """Generate reports in various formats."""
    
    SUPPORTED_FORMATS = ['json', 'csv', 'html', 'xml', 'txt']
    
    def generate_report(self,
                       scan_result: ScanResult, 
                       analysis_result: Optional[SecurityAnalysisResult] = None,
                       report_format: str = 'html',
                       output_path: str = None) -> Optional[str]:
        if report_format.lower() not in self.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported report format: {report_format}")

        try:
            handler = getattr(self, f"_generate_{report_format}_report")
            return handler(scan_result, analysis_result, output_path)
        except Exception as e:
            logger.error(f"Failed to generate {report_format} report: {e}", exc_info=True)
            return None
            
    def _generate_json_report(self, scan_result: ScanResult, analysis_result, output_path) -> Optional[str]:
        # This function seems correct.
        report_data = {
            'metadata': {'generated_at': datetime.now().isoformat()},
            'scan_info': scan_result.scan_info,
            'summary': scan_result.get_summary(),
            'hosts': [h.__dict__ for h in scan_result.hosts]
        }
        if analysis_result:
            report_data['security_analysis'] = analysis_result.get_summary()
            report_data['vulnerabilities'] = analysis_result.vulnerabilities

        if FileHandler.write_json_file(output_path, report_data):
            return output_path
        return None

    def _generate_csv_report(self, scan_result: ScanResult, analysis_result, output_path) -> Optional[str]:
        # This function is also correct.
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            headers = ['IP Address', 'Hostname', 'Port', 'Protocol', 'Service', 'Version']
            if analysis_result:
                headers.append('Vulnerabilities')
            writer.writerow(headers)
            
            for host in scan_result.hosts:
                if host.state != 'up': continue
                for port in host.ports:
                    if port.state != 'open': continue
                    row = [host.ip_address, host.hostname, port.number, port.protocol, port.service, port.version]
                    if analysis_result:
                        vulns = [v['vulnerability'] for v in analysis_result.vulnerabilities if v['host'] == host.ip_address and v.get('port') == port.number]
                        row.append('; '.join(vulns))
                    writer.writerow(row)
        return output_path
        
    def _generate_html_report(self, scan_result: ScanResult, analysis_result, output_path) -> Optional[str]:
        """Generate HTML report."""
        html = "<html><head><title>ReMap Scan Report</title>"
        html += "<style>body{font-family:sans-serif; margin: 2em;} table,th,td{border:1px solid #ccc; border-collapse:collapse; padding:5px;} th{background-color:#f0f0f0;}</style>"
        html += "</head><body>"
        html += f"<h1>ReMap Scan Report - {datetime.now():%Y-%m-%d %H:%M}</h1>"
        
        # CORRECTED: Call the get_summary() method
        summary = scan_result.get_summary()
        html += f"<h2>Summary</h2><p><b>Hosts:</b> {summary.get('hosts_up', 0)}/{summary.get('total_hosts', 0)} up | <b>Open Ports:</b> {summary.get('open_ports', 0)}</p>"

        if analysis_result:
            analysis_summary = analysis_result.get_summary()
            html += f"<p><b>Vulnerabilities Found:</b> {analysis_summary['total_vulnerabilities']}</p>"

        html += "<h2>Hosts and Open Ports</h2><table><tr><th>IP</th><th>Hostname</th><th>Port</th><th>Service</th><th>Version</th></tr>"
        for host in sorted(scan_result.hosts, key=lambda h: h.ip_address):
            if host.state != 'up': continue
            for port in sorted(host.ports, key=lambda p: p.number):
                if port.state != 'open': continue
                html += f"<tr><td>{host.ip_address}</td><td>{host.hostname or ''}</td><td>{port.number}/{port.protocol}</td><td>{port.service or ''}</td><td>{port.version or ''}</td></tr>"
        html += "</table>"
        
        if analysis_result and analysis_result.vulnerabilities:
            html += "<h2>Vulnerabilities</h2><table><tr><th>Severity</th><th>Host</th><th>Port</th><th>Description</th><th>Details</th></tr>"
            severities = ['critical', 'high', 'medium', 'low', 'info']
            for vuln in sorted(analysis_result.vulnerabilities, key=lambda v: severities.index(v['severity'])):
                 html += f"<tr><td>{vuln['severity'].title()}</td><td>{vuln['host']}</td><td>{vuln['port'] or 'N/A'}</td><td>{vuln['vulnerability']}</td><td>{vuln.get('details', '')}</td></tr>"
            html += "</table>"

        html += "</body></html>"
        if FileHandler.write_text_file(output_path, html):
            return output_path
        return None

    def _generate_xml_report(self, scan_result, analysis_result, output_path) -> Optional[str]:
        # This function seems correct.
        root = ET.Element("RemapReport")
        for host in scan_result.hosts:
            host_el = ET.SubElement(root, "Host", attrib={'ip': host.ip_address, 'state': host.state})
            for port in host.ports:
                ET.SubElement(host_el, "Port", attrib={'id': str(port.number), 'state': port.state, 'service': port.service or ''})
        
        xml_str = ET.tostring(root, 'unicode')
        dom = minidom.parseString(xml_str)
        pretty_xml = dom.toprettyxml(indent="  ")

        if FileHandler.write_text_file(output_path, pretty_xml):
            return output_path
        return None

    def _generate_text_report(self, scan_result, analysis_result, output_path) -> Optional[str]:
        # This function is correct.
        lines = ["="*40, f" ReMap Scan Report - {datetime.now():%Y-%m-%d %H:%M}", "="*40 + "\n"]
        for host in scan_result.hosts:
            if host.state != 'up': continue
            lines.append(f"Host: {host.ip_address} ({host.hostname or 'N/A'})")
            for port in host.ports:
                if port.state != 'open': continue
                lines.append(f"  - Port {port.number}/{port.protocol}: {port.service or 'unknown'} ({port.version or ''})")
        
        if FileHandler.write_text_file(output_path, "\n".join(lines)):
            return output_path
        return None