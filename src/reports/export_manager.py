"""Export manager for handling various report export formats."""

import json
import csv
from typing import Dict, Any, List, Optional
from pathlib import Path
from datetime import datetime
import zipfile
import tempfile
import os

from .report_generator import ReportGenerator
from ..models.scan_result import ScanResult
from ..analysis.security_analyzer import SecurityAnalysisResult
from ..utils.logger import setup_logger
from ..utils.file_handler import FileHandler

logger = setup_logger(__name__)

class ExportManager:
    """Manage report exports in various formats."""
    
    def __init__(self):
        self.report_generator = ReportGenerator()
        self.export_history = []
    
    def export_comprehensive_report(self, scan_result: ScanResult,
                                  analysis_result: Optional[SecurityAnalysisResult] = None,
                                  export_formats: List[str] = None,
                                  output_directory: str = None) -> Dict[str, str]:
        """
        Export comprehensive report in multiple formats.
        
        Args:
            scan_result: Scan results to export
            analysis_result: Security analysis results (optional)
            export_formats: List of formats to export (default: all)
            output_directory: Output directory (default: ~/.remap/reports)
            
        Returns:
            Dictionary mapping format to output file path
        """
        try:
            if export_formats is None:
                export_formats = ['html', 'json', 'csv', 'txt']
            
            if output_directory is None:
                output_directory = str(Path.home() / ".remap" / "reports")
            
            # Ensure output directory exists
            FileHandler.ensure_directory_exists(output_directory)
            
            # Generate timestamp for file naming
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"remap_report_{timestamp}"
            
            export_results = {}
            
            for format_type in export_formats:
                try:
                    output_path = os.path.join(output_directory, f"{base_filename}.{format_type}")
                    
                    generated_path = self.report_generator.generate_report(
                        scan_result, analysis_result, format_type, output_path
                    )
                    
                    if generated_path:
                        export_results[format_type] = generated_path
                        logger.info(f"Exported {format_type.upper()} report: {generated_path}")
                    else:
                        logger.warning(f"Failed to export {format_type} report")
                        
                except Exception as e:
                    logger.error(f"Failed to export {format_type} report: {e}")
                    continue
            
            # Add to export history
            self._add_to_history(export_results, scan_result, analysis_result)
            
            logger.info(f"Comprehensive export completed: {len(export_results)} formats")
            return export_results
            
        except Exception as e:
            logger.error(f"Comprehensive export failed: {e}")
            raise
    
    def export_vulnerability_report(self, analysis_result: SecurityAnalysisResult,
                                   format_type: str = 'csv',
                                   output_path: str = None) -> str:
        """
        Export vulnerability-focused report.
        
        Args:
            analysis_result: Security analysis results
            format_type: Export format (csv, json, html)
            output_path: Output file path
            
        Returns:
            Path to exported file
        """
        try:
            if not analysis_result.vulnerabilities:
                logger.warning("No vulnerabilities found to export")
                return ""
            
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"vulnerabilities_report_{timestamp}.{format_type}"
                output_path = str(Path.home() / ".remap" / "reports" / filename)
            
            # Ensure output directory exists
            FileHandler.ensure_directory_exists(str(Path(output_path).parent))
            
            if format_type.lower() == 'csv':
                return self._export_vulnerabilities_csv(analysis_result, output_path)
            elif format_type.lower() == 'json':
                return self._export_vulnerabilities_json(analysis_result, output_path)
            elif format_type.lower() == 'html':
                return self._export_vulnerabilities_html(analysis_result, output_path)
            else:
                raise ValueError(f"Unsupported vulnerability export format: {format_type}")
                
        except Exception as e:
            logger.error(f"Vulnerability report export failed: {e}")
            raise
    
    def export_web_services_report(self, analysis_result: SecurityAnalysisResult,
                                 format_type: str = 'csv',
                                 output_path: str = None) -> str:
        """
        Export web services report.
        
        Args:
            analysis_result: Security analysis results
            format_type: Export format (csv, json)
            output_path: Output file path
            
        Returns:
            Path to exported file
        """
        try:
            if not analysis_result.web_services:
                logger.warning("No web services found to export")
                return ""
            
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"web_services_{timestamp}.{format_type}"
                output_path = str(Path.home() / ".remap" / "reports" / filename)
            
            # Ensure output directory exists
            FileHandler.ensure_directory_exists(str(Path(output_path).parent))
            
            if format_type.lower() == 'csv':
                return self._export_web_services_csv(analysis_result, output_path)
            elif format_type.lower() == 'json':
                return self._export_web_services_json(analysis_result, output_path)
            else:
                raise ValueError(f"Unsupported web services export format: {format_type}")
                
        except Exception as e:
            logger.error(f"Web services report export failed: {e}")
            raise
    
    def create_export_package(self, scan_result: ScanResult,
                            analysis_result: Optional[SecurityAnalysisResult] = None,
                            output_path: str = None) -> str:
        """
        Create ZIP package with all report formats and raw data.
        
        Args:
            scan_result: Scan results
            analysis_result: Security analysis results
            output_path: Output ZIP file path
            
        Returns:
            Path to created ZIP file
        """
        try:
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"remap_export_package_{timestamp}.zip"
                output_path = str(Path.home() / ".remap" / "exports" / filename)
            
            # Ensure output directory exists
            FileHandler.ensure_directory_exists(str(Path(output_path).parent))
            
            # Create temporary directory for files
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Export all formats to temp directory
                formats = ['html', 'json', 'csv', 'xml', 'txt']
                exported_files = []
                
                for format_type in formats:
                    try:
                        report_path = temp_path / f"scan_report.{format_type}"
                        generated = self.report_generator.generate_report(
                            scan_result, analysis_result, format_type, str(report_path)
                        )
                        if generated:
                            exported_files.append(generated)
                    except Exception as e:
                        logger.warning(f"Failed to include {format_type} in package: {e}")
                
                # Export specialized reports if analysis available
                if analysis_result:
                    if analysis_result.vulnerabilities:
                        vuln_csv = temp_path / "vulnerabilities.csv"
                        try:
                            vuln_path = self._export_vulnerabilities_csv(analysis_result, str(vuln_csv))
                            if vuln_path:
                                exported_files.append(vuln_path)
                        except Exception as e:
                            logger.warning(f"Failed to include vulnerabilities CSV: {e}")
                    
                    if analysis_result.web_services:
                        web_csv = temp_path / "web_services.csv"
                        try:
                            web_path = self._export_web_services_csv(analysis_result, str(web_csv))
                            if web_path:
                                exported_files.append(web_path)
                        except Exception as e:
                            logger.warning(f"Failed to include web services CSV: {e}")
                
                # Create summary file
                summary_path = temp_path / "export_summary.txt"
                self._create_export_summary(scan_result, analysis_result, str(summary_path))
                exported_files.append(str(summary_path))
                
                # Create ZIP package
                with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file_path in exported_files:
                        if os.path.exists(file_path):
                            arcname = os.path.basename(file_path)
                            zipf.write(file_path, arcname)
                            logger.debug(f"Added to ZIP: {arcname}")
                
                logger.info(f"Export package created: {output_path}")
                return output_path
                
        except Exception as e:
            logger.error(f"Failed to create export package: {e}")
            raise
    
    def _export_vulnerabilities_csv(self, analysis_result: SecurityAnalysisResult, 
                                  output_path: str) -> str:
        """Export vulnerabilities to CSV format."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'Host', 'Port', 'Vulnerability', 'Severity', 
                    'Details', 'Timestamp'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for vuln in analysis_result.vulnerabilities:
                    writer.writerow({
                        'Host': vuln['host'],
                        'Port': vuln.get('port', ''),
                        'Vulnerability': vuln['vulnerability'],
                        'Severity': vuln.get('severity', 'medium').title(),
                        'Details': vuln.get('details', ''),
                        'Timestamp': vuln.get('timestamp', '').isoformat() if vuln.get('timestamp') else ''
                    })
            
            logger.info(f"Vulnerabilities CSV exported: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to export vulnerabilities CSV: {e}")
            raise
    
    def _export_vulnerabilities_json(self, analysis_result: SecurityAnalysisResult, 
                                   output_path: str) -> str:
        """Export vulnerabilities to JSON format."""
        try:
            vuln_data = {
                'export_info': {
                    'generated_at': datetime.now().isoformat(),
                    'total_vulnerabilities': len(analysis_result.vulnerabilities),
                    'summary': analysis_result.get_summary()
                },
                'vulnerabilities': []
            }
            
            for vuln in analysis_result.vulnerabilities:
                vuln_copy = vuln.copy()
                if 'timestamp' in vuln_copy and vuln_copy['timestamp']:
                    vuln_copy['timestamp'] = vuln_copy['timestamp'].isoformat()
                vuln_data['vulnerabilities'].append(vuln_copy)
            
            if FileHandler.write_json_file(output_path, vuln_data):
                logger.info(f"Vulnerabilities JSON exported: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write JSON file")
                
        except Exception as e:
            logger.error(f"Failed to export vulnerabilities JSON: {e}")
            raise
    
    def _export_vulnerabilities_html(self, analysis_result: SecurityAnalysisResult, 
                                   output_path: str) -> str:
        """Export vulnerabilities to HTML format."""
        try:
            # Group vulnerabilities by severity
            vuln_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
            
            for vuln in analysis_result.vulnerabilities:
                severity = vuln.get('severity', 'medium').lower()
                if severity in vuln_by_severity:
                    vuln_by_severity[severity].append(vuln)
            
            # Build HTML content
            html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReMap Vulnerability Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; text-align: center; }}
        .severity-section {{ margin-bottom: 30px; }}
        .severity-header {{ padding: 10px; border-radius: 5px; margin-bottom: 10px; color: white; text-align: center; }}
        .critical {{ background-color: #dc3545; }}
        .high {{ background-color: #fd7e14; }}
        .medium {{ background-color: #ffc107; color: #333; }}
        .low {{ background-color: #28a745; }}
        .vulnerability {{ background: #f8f9fa; padding: 15px; margin-bottom: 10px; border-radius: 5px; border-left: 4px solid #667eea; }}
        .vuln-title {{ font-weight: bold; font-size: 16px; margin-bottom: 5px; }}
        .vuln-details {{ margin: 5px 0; }}
        .stats {{ display: flex; justify-content: space-around; margin-bottom: 20px; }}
        .stat {{ text-align: center; }}
        .stat-number {{ font-size: 24px; font-weight: bold; color: #667eea; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{len(vuln_by_severity['critical'])}</div>
                <div>Critical</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(vuln_by_severity['high'])}</div>
                <div>High</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(vuln_by_severity['medium'])}</div>
                <div>Medium</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(vuln_by_severity['low'])}</div>
                <div>Low</div>
            </div>
        </div>
        
        {self._build_vulnerability_sections_html(vuln_by_severity)}
    </div>
</body>
</html>
"""
            
            if FileHandler.write_text_file(output_path, html_content):
                logger.info(f"Vulnerabilities HTML exported: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write HTML file")
                
        except Exception as e:
            logger.error(f"Failed to export vulnerabilities HTML: {e}")
            raise
    
    def _build_vulnerability_sections_html(self, vuln_by_severity: Dict[str, List]) -> str:
        """Build HTML sections for vulnerabilities by severity."""
        sections = []
        
        severity_order = ['critical', 'high', 'medium', 'low']
        severity_titles = {
            'critical': 'Critical Vulnerabilities',
            'high': 'High Severity Vulnerabilities', 
            'medium': 'Medium Severity Vulnerabilities',
            'low': 'Low Severity Vulnerabilities'
        }
        
        for severity in severity_order:
            vulnerabilities = vuln_by_severity.get(severity, [])
            if not vulnerabilities:
                continue
            
            section_html = f"""
        <div class="severity-section">
            <div class="severity-header {severity}">
                <h2>{severity_titles[severity]} ({len(vulnerabilities)})</h2>
            </div>
            """
            
            for vuln in vulnerabilities:
                port_info = f":{vuln['port']}" if vuln.get('port') else ""
                timestamp_info = ""
                if vuln.get('timestamp'):
                    timestamp_info = f"<div class='vuln-details'><strong>Detected:</strong> {vuln['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if hasattr(vuln['timestamp'], 'strftime') else str(vuln['timestamp'])}</div>"
                
                section_html += f"""
            <div class="vulnerability">
                <div class="vuln-title">{vuln['vulnerability']}</div>
                <div class="vuln-details"><strong>Host:</strong> {vuln['host']}{port_info}</div>
                <div class="vuln-details"><strong>Severity:</strong> {vuln.get('severity', 'medium').title()}</div>
                {timestamp_info}
                <div class="vuln-details"><strong>Details:</strong> {vuln.get('details', 'No additional details available')}</div>
            </div>
                """
            
            section_html += "</div>"
            sections.append(section_html)
        
        return "\n".join(sections)
    
    def _export_web_services_csv(self, analysis_result: SecurityAnalysisResult, 
                               output_path: str) -> str:
        """Export web services to CSV format."""
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'Host', 'Port', 'URL', 'Server', 'Applications', 
                    'Status Code', 'Content Type', 'Security Headers'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for web_service in analysis_result.web_services:
                    result = web_service.get('result', {})
                    server_info = result.get('server_info', {})
                    applications = result.get('applications', [])
                    security_headers = result.get('security_headers', {})
                    urls = result.get('urls', [])
                    
                    # Count missing security headers
                    missing_headers = sum(1 for h in security_headers.values() 
                                        if not h.get('present', False))
                    security_summary = f"{len(security_headers) - missing_headers}/{len(security_headers)} present"
                    
                    writer.writerow({
                        'Host': web_service['host'],
                        'Port': web_service['port'],
                        'URL': urls[0] if urls else f"http://{web_service['host']}:{web_service['port']}",
                        'Server': server_info.get('server', 'Unknown'),
                        'Applications': ', '.join([app.get('name', '') for app in applications]),
                        'Status Code': server_info.get('status_code', ''),
                        'Content Type': server_info.get('content_type', ''),
                        'Security Headers': security_summary
                    })
            
            logger.info(f"Web services CSV exported: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to export web services CSV: {e}")
            raise
    
    def _export_web_services_json(self, analysis_result: SecurityAnalysisResult, 
                                output_path: str) -> str:
        """Export web services to JSON format."""
        try:
            web_data = {
                'export_info': {
                    'generated_at': datetime.now().isoformat(),
                    'total_web_services': len(analysis_result.web_services)
                },
                'web_services': analysis_result.web_services
            }
            
            if FileHandler.write_json_file(output_path, web_data):
                logger.info(f"Web services JSON exported: {output_path}")
                return output_path
            else:
                raise Exception("Failed to write JSON file")
                
        except Exception as e:
            logger.error(f"Failed to export web services JSON: {e}")
            raise
    
    def _create_export_summary(self, scan_result: ScanResult,
                             analysis_result: Optional[SecurityAnalysisResult],
                             output_path: str):
        """Create export summary text file."""
        try:
            lines = []
            lines.append("ReMap Export Package Summary")
            lines.append("=" * 40)
            lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append("")
            
            # Scan summary
            lines.append("SCAN SUMMARY:")
            lines.append(f"  Total Hosts: {scan_result.total_hosts}")
            lines.append(f"  Hosts Up: {scan_result.hosts_up}")
            if scan_result.duration:
                lines.append(f"  Scan Duration: {scan_result.duration:.1f}s")
            lines.append("")
            
            # Analysis summary
            if analysis_result:
                summary = analysis_result.get_summary()
                lines.append("ANALYSIS SUMMARY:")
                lines.append(f"  Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
                
                severity_breakdown = summary.get('severity_breakdown', {})
                for severity, count in severity_breakdown.items():
                    lines.append(f"  {severity.title()}: {count}")
                
                lines.append(f"  Web Services Found: {summary.get('web_services_found', 0)}")
                lines.append("")
            
            # Files included
            lines.append("FILES INCLUDED:")
            lines.append("  - scan_report.html (Main HTML report)")
            lines.append("  - scan_report.json (Detailed JSON data)")
            lines.append("  - scan_report.csv (Tabular data)")
            lines.append("  - scan_report.xml (XML format)")
            lines.append("  - scan_report.txt (Text summary)")
            
            if analysis_result and analysis_result.vulnerabilities:
                lines.append("  - vulnerabilities.csv (Vulnerability details)")
            
            if analysis_result and analysis_result.web_services:
                lines.append("  - web_services.csv (Web service details)")
            
            lines.append("  - export_summary.txt (This file)")
            
            content = "\n".join(lines)
            FileHandler.write_text_file(output_path, content)
            
        except Exception as e:
            logger.error(f"Failed to create export summary: {e}")
    
    def _add_to_history(self, export_results: Dict[str, str], 
                       scan_result: ScanResult,
                       analysis_result: Optional[SecurityAnalysisResult]):
        """Add export to history."""
        try:
            history_entry = {
                'timestamp': datetime.now().isoformat(),
                'formats': list(export_results.keys()),
                'files': export_results,
                'scan_stats': {
                    'total_hosts': scan_result.total_hosts,
                    'hosts_up': scan_result.hosts_up,
                    'duration': scan_result.duration
                }
            }
            
            if analysis_result:
                summary = analysis_result.get_summary()
                history_entry['analysis_stats'] = summary
            
            self.export_history.append(history_entry)
            
            # Keep only last 50 entries
            if len(self.export_history) > 50:
                self.export_history = self.export_history[-50:]
                
        except Exception as e:
            logger.error(f"Failed to add export to history: {e}")
    
    def get_export_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent export history."""
        return self.export_history[-limit:] if self.export_history else []
    
    def clear_export_history(self):
        """Clear export history."""
        self.export_history.clear()
        logger.info("Export history cleared")