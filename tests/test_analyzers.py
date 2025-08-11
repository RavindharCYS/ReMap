"""Tests for security analyzers."""

import unittest
from unittest.mock import patch, MagicMock
from src.analysis.security_analyzer import SecurityAnalyzer
from src.models.scan_result import ScanResult

class TestSecurityAnalyzer(unittest.TestCase):

    def setUp(self):
        """Set up a mock scanner and a basic ScanResult object."""
        self.analyzer = SecurityAnalyzer()
        self.scan_result = ScanResult()
        # Add a mock host to the result for testing
        mock_host = MagicMock()
        mock_host.state = 'up'
        self.scan_result.hosts.append(mock_host)

    def test_analyze_no_options(self):
        """Test that analysis runs without error when no options are selected."""
        analysis_options = {
            'tls_check': False, 'ssl_check': False, 
            'smb_check': False, 'web_detection': False
        }
        result = self.analyzer.analyze_scan_results(self.scan_result, analysis_options)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.vulnerabilities), 0)

    # Mocking is complex for network tools, so this is a placeholder.
    # Full integration tests would be needed.
    @patch('src.analysis.tls_analyzer.TLSAnalyzer.bulk_analyze')
    def test_tls_analysis_runs(self, mock_bulk_analyze):
        """Test if the TLS analysis is called when the option is enabled."""
        mock_bulk_analyze.return_value = []
        analysis_options = {'tls_check': True}
        
        self.analyzer.analyze_scan_results(self.scan_result, analysis_options)
        
        # Check that the bulk_analyze method of the TLSAnalyzer was called
        mock_bulk_analyze.assert_called()

if __name__ == '__main__':
    unittest.main()