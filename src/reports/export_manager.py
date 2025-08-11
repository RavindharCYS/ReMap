"""Export manager for handling various report export formats."""

import os
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

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

    def export_comprehensive_report(self,
                                  scan_result: ScanResult,
                                  analysis_result: Optional[SecurityAnalysisResult] = None,
                                  export_formats: Optional[List[str]] = None,
                                  output_directory: Optional[str] = None) -> Dict[str, str]:
        """Export a comprehensive report in one or more formats."""
        if export_formats is None:
            export_formats = ['html', 'json', 'csv']
        
        if output_directory is None:
            output_directory = str(Path.home() / ".remap" / "reports")
        FileHandler.ensure_directory_exists(output_directory)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"remap_report_{timestamp}"
        
        exported_files: Dict[str, str] = {}
        for fmt in export_formats:
            try:
                output_path = os.path.join(output_directory, f"{base_filename}.{fmt}")
                generated_path = self.report_generator.generate_report(
                    scan_result, analysis_result, fmt, output_path
                )
                if generated_path:
                    exported_files[fmt] = generated_path
                    logger.info(f"Exported {fmt.upper()} report to: {generated_path}")
                else:
                    logger.warning(f"Failed to generate {fmt} report.")
            except Exception as e:
                logger.error(f"Failed to export {fmt} report: {e}", exc_info=True)

        return exported_files

    def create_export_package(self,
                              scan_result: ScanResult,
                              analysis_result: Optional[SecurityAnalysisResult] = None,
                              output_path: Optional[str] = None) -> str:
        """Create a ZIP package with all report formats."""
        if output_path is None:
            exports_dir = str(Path.home() / ".remap" / "exports")
            FileHandler.ensure_directory_exists(exports_dir)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(exports_dir, f"remap_export_package_{timestamp}.zip")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Export all supported formats into the temporary directory
            formats_to_export = ['html', 'json', 'csv', 'xml', 'txt']
            self.export_comprehensive_report(
                scan_result, analysis_result, formats_to_export, temp_dir
            )
            
            # Create the zip file
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, arcname=os.path.basename(file_path))

            logger.info(f"Export package created: {output_path}")
            return output_path