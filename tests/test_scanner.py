"""Tests for the core scanner logic."""

import unittest
from unittest.mock import MagicMock, patch
from src.core.scanner import Scanner
from src.models.settings import ScanSettings

class TestScanner(unittest.TestCase):

    @patch('src.core.nmap_wrapper.NmapWrapper')
    def test_scanner_creation(self, MockNmapWrapper):
        """Test if the Scanner can be initialized."""
        mock_wrapper_instance = MockNmapWrapper.return_value
        mock_wrapper_instance.test_nmap.return_value = True

        settings = ScanSettings()
        scanner = Scanner(settings)
        self.assertIsInstance(scanner, Scanner)
        MockNmapWrapper.assert_called_with(settings)

    @patch('src.core.nmap_wrapper.NmapWrapper')
    def test_start_scan_no_targets(self, MockNmapWrapper):
        """Test that start_scan returns False if no targets are provided."""
        settings = ScanSettings()
        scanner = Scanner(settings)
        result = scanner.start_scan(targets=[], scan_type="fast")
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main()