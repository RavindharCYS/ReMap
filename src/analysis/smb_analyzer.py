"""SMB service analyzer."""

import socket
import struct
from typing import Dict, Any, Optional, List
import concurrent.futures

from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SMBAnalyzer:
    """Analyzer for SMB services and configurations."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def analyze_smb_signing(self, host: str) -> Optional[Dict[str, Any]]:
        """Analyze SMB signing configuration."""
        result = {
            'host': host,
            'signing_required': None,
            'signing_enabled': None,
            'version': None,
            'vulnerabilities': [],
            'ports_tested': []
        }

        # Test both SMB ports
        for port in [445, 139]:
            if result['version']: continue  # Stop if we found a version
            try:
                port_result = self._test_smb_port(host, port)
                if port_result:
                    result['ports_tested'].append(port)
                    result.update(port_result)
            except Exception as e:
                logger.debug(f"SMB test failed for {host}:{port}: {e}")

        if not result['ports_tested']:
            return None

        result['vulnerabilities'] = self._check_smb_vulnerabilities(result)
        return result

    def _test_smb_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Test SMB on a specific port."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                if port == 445:
                    return self._test_direct_smb(s)
                elif port == 139:
                    return self._test_netbios_session(s, host)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None
        return None

    def _test_direct_smb(self, s: socket.socket) -> Optional[Dict[str, Any]]:
        """Test direct SMB (port 445)."""
        negotiate_request = self._build_smb2_negotiate()
        s.send(negotiate_request)
        response = s.recv(1024)
        if len(response) < 4: return None
        return self._parse_smb_response(response[4:]) # Skip NetBIOS header

    def _test_netbios_session(self, s: socket.socket, host: str) -> Optional[Dict[str, Any]]:
        """Test NetBIOS session (port 139)."""
        session_request = self._build_netbios_session_request(host)
        s.send(session_request)
        response = s.recv(1024)
        if not response or response[0] != 0x82: # Positive session response
            return None
        
        negotiate_request = self._build_smb1_negotiate()
        s.send(negotiate_request)
        smb_response = s.recv(1024)
        if len(smb_response) < 4: return None
        return self._parse_smb_response(smb_response[4:]) # Skip NetBIOS header

    def _build_smb2_negotiate(self) -> bytes:
        """Builds a SMB2 NEGOTIATE_PROTOCOL request."""
        header = b'\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        data = b'\x24\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x78\x00\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03'
        smb_packet = header + data
        netbios_header = struct.pack('>I', len(smb_packet))
        return netbios_header + smb_packet

    def _build_smb1_negotiate(self) -> bytes:
        """Builds a SMB1 NEGOTIATE_PROTOCOL request."""
        smb_header = b'\xffSMB\x72\x00\x00\x00\x00\x18\x01\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00'
        dialects = b'\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00\x02LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00\x02NT LM 0.12\x00'
        byte_count = struct.pack('<H', len(dialects))
        word_count = b'\x00'
        smb_packet = smb_header + word_count + byte_count + dialects
        netbios_header = struct.pack('>I', len(smb_packet))
        return netbios_header + smb_packet
        
    def _build_netbios_session_request(self, host: str) -> bytes:
        """Builds a NetBIOS Session Request Packet."""
        encoded_host = self._encode_netbios_name(host.upper())
        encoded_caller = self._encode_netbios_name('REMAPCLIENT')
        packet = b'\x81\x00\x00\x44' + encoded_host + encoded_caller
        return packet

    def _encode_netbios_name(self, name: str) -> bytes:
        """Encodes a name for NetBIOS requests."""
        name = name.ljust(15, ' ')[:15] + '\x00'
        encoded = b''
        for char in name.encode('ascii'):
            encoded += struct.pack('B', (char >> 4) + 0x41)
            encoded += struct.pack('B', (char & 0x0f) + 0x41)
        return encoded
    
    def _parse_smb_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parses a SMB negotiate response for SMB1 or SMB2."""
        if not response: return None
        # Check for SMB2/3
        if response.startswith(b'\xfeSMB'):
            return self._parse_smb2_negotiate_response(response)
        # Check for SMB1
        if response.startswith(b'\xffSMB'):
            return self._parse_smb1_negotiate_response(response)
        return None

    def _parse_smb2_negotiate_response(self, data: bytes) -> Dict[str, Any]:
        """Parses a SMB2 Negotiate Response."""
        security_mode = struct.unpack('<H', data[64:66])[0]
        dialect_revision = struct.unpack('<H', data[66:68])[0]
        
        dialects = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1"}
        version = f"SMB {dialects.get(dialect_revision, 'Unknown')}"

        return {
            'version': version,
            'signing_enabled': bool(security_mode & 0x01),
            'signing_required': bool(security_mode & 0x02),
        }

    def _parse_smb1_negotiate_response(self, data: bytes) -> Dict[str, Any]:
        """Parses a SMB1 Negotiate Response."""
        security_mode = struct.unpack('<H', data[39:41])[0]
        return {
            'version': 'SMB 1.0',
            'signing_enabled': bool(security_mode & 0x04),
            'signing_required': bool(security_mode & 0x08),
        }

    def _check_smb_vulnerabilities(self, smb_result: Dict[str, Any]) -> List[str]:
        """Check for SMB vulnerabilities."""
        vulnerabilities = []
        if not smb_result.get('signing_required'):
            vulnerabilities.append('SMB signing not required')
        if smb_result.get('version') == 'SMB 1.0':
            vulnerabilities.append('SMBv1 enabled (vulnerable)')
        return vulnerabilities

    def bulk_analyze(self, targets: List[str], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Analyze multiple SMB targets concurrently."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {executor.submit(self.analyze_smb_signing, h): h for h in targets}
            for future in concurrent.futures.as_completed(future_to_target):
                result = future.result()
                if result:
                    results.append(result)
        return results