"""Tests for target and XML parsers."""

import unittest
from src.core.target_parser import TargetParser
from src.models.target import Target

class TestTargetParser(unittest.TestCase):

    def test_parse_single_ip(self):
        """Test parsing a single IP address."""
        targets = TargetParser.parse_target_string("192.168.1.1")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0], Target(ip_address="192.168.1.1"))

    def test_parse_ip_with_ports(self):
        """Test parsing an IP with multiple ports."""
        targets = TargetParser.parse_target_string("10.0.0.1:80,443")
        self.assertEqual(len(targets), 1)
        # Note: ports are stored as a tuple
        self.assertEqual(targets[0], Target(ip_address="10.0.0.1", ports=(80, 443)))

    def test_parse_mixed_input(self):
        """Test parsing a string with multiple lines and formats."""
        input_str = """
        # This is a comment
        192.168.1.10
        
        10.0.0.5:22
        scanme.nmap.org
        """
        targets = TargetParser.parse_target_string(input_str)
        self.assertEqual(len(targets), 3)
        self.assertIn(Target(ip_address="192.168.1.10"), targets)
        self.assertIn(Target(ip_address="10.0.0.5", ports=(22,)), targets)
        self.assertIn(Target(ip_address="scanme.nmap.org"), targets)

    def test_parse_invalid_line(self):
        """Test that invalid lines are skipped."""
        input_str = "192.168.1.256\ninvalid-target\n10.0.0.1"
        targets = TargetParser.parse_target_string(input_str)
        # This behavior depends on how strict the parser is.
        # Assuming the validator-based parser skips invalids:
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ip_address, "10.0.0.1")

if __name__ == '__main__':
    unittest.main()