"""XML loader for existing Nmap reports."""

from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.xml_parser import NmapXMLParser
from ..models.scan_result import ScanResult
from ..utils.logger import setup_logger
from ..utils.validators import Validators

logger = setup_logger(__name__)

class XMLLoader:
    """Load and manage existing XML scan reports."""
    
    def __init__(self):
        self.parser = NmapXMLParser()
    
    def load_xml_report(self, xml_file_path: str) -> Optional[ScanResult]:
        """Load Nmap XML report."""
        if not Validators.validate_xml_file(xml_file_path):
            logger.error(f"Invalid or non-existent XML file path: {xml_file_path}")
            raise ValueError(f"Invalid XML file: {xml_file_path}")
            
        try:
            scan_result = self.parser.parse_xml_file(xml_file_path)
            logger.info(f"Successfully loaded XML report: {xml_file_path}")
            return scan_result
        except Exception as e:
            logger.error(f"Failed to load XML report {xml_file_path}: {e}", exc_info=True)
            return None
    
    def load_multiple_xml_reports(self, xml_file_paths: List[str]) -> List[ScanResult]:
        """Load multiple XML reports."""
        results = []
        for path in xml_file_paths:
            try:
                if (result := self.load_xml_report(path)):
                    results.append(result)
            except ValueError:
                # Logged in load_xml_report
                continue
        return results
    
    def merge_xml_reports(self, xml_file_paths: List[str]) -> Optional[ScanResult]:
        """Load and merge multiple XML reports into a single ScanResult."""
        if not xml_file_paths: return None
        try:
            return self.parser.merge_xml_files(xml_file_paths)
        except Exception as e:
            logger.error(f"Failed to merge XML reports: {e}", exc_info=True)
            return None