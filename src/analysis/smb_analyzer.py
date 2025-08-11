"""SMB service analyzer."""

import socket
import struct
from typing import Dict, Any, Optional, List
import concurrent.futures

from ..utils.logger import setup_logger

logger = setup_logger(__name__)

class SMBAnalyzer:
    """Analyzer for SMB services and configurations."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def analyze_smb_signing(self, host: str) -> Optional[Dict[str, Any]]:
        """
        Analyze SMB signing configuration.
        
        Returns:
            Dictionary with SMB analysis results or None if failed
        """
        try:
            result = {
                'host': host,
                'signing_required': None,
                'signing_enabled': None,
                'version': None,
                'vulnerabilities': [],
                'ports_tested': []
            }
            
            # Test both SMB ports
            for port in [139, 445]:
                try:
                    port_result = self._test_smb_port(host, port)
                    if port_result:
                        result['ports_tested'].append(port)
                        
                        # Update result with findings
                        if result['signing_required'] is None:
                            result['signing_required'] = port_result.get('signing_required')
                        
                        if result['signing_enabled'] is None:
                            result['signing_enabled'] = port_result.get('signing_enabled')
                        
                        if result['version'] is None:
                            result['version'] = port_result.get('version')
                        
                except Exception as e:
                    logger.debug(f"SMB test failed for {host}:{port}: {e}")
            
            if not result['ports_tested']:
                return None
            
            # Analyze for vulnerabilities
            result['vulnerabilities'] = self._check_smb_vulnerabilities(result)
            
            return result
            
        except Exception as e:
            logger.error(f"SMB analysis failed for {host}: {e}")
            return None
    
    def _test_smb_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Test SMB on a specific port."""
        try:
            if port == 139:
                return self._test_netbios_session(host, port)
            elif port == 445:
                return self._test_direct_smb(host, port)
        except Exception as e:
            logger.debug(f"SMB port test failed for {host}:{port}: {e}")
        
        return None
    
    def _test_direct_smb(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Test direct SMB (port 445)."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                # SMB2/3 Negotiate Protocol Request
                negotiate_request = self._build_smb2_negotiate()
                sock.send(negotiate_request)
                
                # Receive response
                response = sock.recv(4096)
                if len(response) < 64:
                    return None
                
                return self._parse_smb2_negotiate_response(response)
                
        except Exception as e:
            logger.debug(f"Direct SMB test failed for {host}:{port}: {e}")
        
        return None
    
    def _test_netbios_session(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Test NetBIOS session (port 139)."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                # NetBIOS Session Request
                session_request = self._build_netbios_session_request(host)
                sock.send(session_request)
                
                # Receive NetBIOS response
                response = sock.recv(4096)
                if len(response) < 4:
                    return None
                
                # Check if session was established
                if response[0] == 0x82:  # Positive session response
                    # Send SMB negotiate
                    negotiate_request = self._build_smb1_negotiate()
                    sock.send(negotiate_request)
                    
                    # Receive SMB response
                    smb_response = sock.recv(4096)
                    if len(smb_response) > 32:
                        return self._parse_smb1_negotiate_response(smb_response)
                
        except Exception as e:
            logger.debug(f"NetBIOS session test failed for {host}:{port}: {e}")
        
        return None
    
    def _build_smb2_negotiate(self) -> bytes:
        """Build SMB2 negotiate protocol request."""
        # SMB2 Header
        protocol_id = b'\xfeSMB'
        structure_size = 64
        credit_charge = 0
        channel_sequence = 0
        reserved = 0
        command = 0  # SMB2_NEGOTIATE
        credits_requested = 1
        flags = 0
        next_command = 0
        message_id = 0
        reserved2 = 0
        tree_id = 0
        session_id = 0
        signature = b'\x00' * 16
        
        header = struct.pack('<4sHHHHHHHIIIQ16s',
                           protocol_id, structure_size, credit_charge,
                           channel_sequence, reserved, command, credits_requested,
                           flags, next_command, message_id, reserved2, tree_id,
                           session_id, signature)
        
        # SMB2 Negotiate Request
        negotiate_structure_size = 36
        dialect_count = 3  # SMB 2.0.2, 2.1, 3.0
        security_mode = 1  # Signing enabled but not required
        reserved3 = 0
        capabilities = 1  # DFS capability
        client_guid = b'\x00' * 16
        client_start_time = 0
        dialects = struct.pack('<HHH', 0x0202, 0x0210, 0x0300)  # SMB dialects
        
        negotiate_data = struct.pack('<HHHHI16sQ',
                                   negotiate_structure_size, dialect_count,
                                   security_mode, reserved3, capabilities,
                                   client_guid, client_start_time) + dialects
        
        # NetBIOS Session Service header
        netbios_header = struct.pack('>BxH', 0, len(header + negotiate_data))
        
        return netbios_header + header + negotiate_data
    
    def _build_smb1_negotiate(self) -> bytes:
        """Build SMB1 negotiate protocol request."""
        # NetBIOS header
        netbios_type = 0  # Session message
        netbios_flags = 0
        
        # SMB1 header
        protocol = b'\xffSMB'
        command = 0x72  # SMB_COM_NEGOTIATE
        error_class = 0
        reserved1 = 0
        error_code = 0
        flags = 0x18  # Canonical pathnames, case insensitive
        flags2 = 0xC853  # Long names, EAs, NT status, unicode
        tree_id = 0
        process_id = 0xFEFF
        user_id = 0
        multiplex_id = 0
        
        smb_header = struct.pack('<4sBBBBBBHHHHHH',
                               protocol, command, error_class, reserved1,
                               error_code, flags, flags2, tree_id,
                               process_id, user_id, multiplex_id, 0)
        
        # Negotiate request data
        word_count = 0
        byte_count = 12
        dialects = b'\x02NT LM 0.12\x00'
        
        negotiate_data = struct.pack('<BH', word_count, byte_count) + dialects
        
        # Complete message
        message = smb_header + negotiate_data
        netbios_header = struct.pack('>BxH', netbios_type, len(message))
        
        return netbios_header + message
    
    def _build_netbios_session_request(self, host: str) -> bytes:
        """Build NetBIOS session request."""
        # NetBIOS names are 16 bytes, padded with spaces
        called_name = b'*SMBSERVER      '  # Generic SMB server name
        calling_name = b'REMAP           '  # Our client name
        
        session_request = struct.pack('>BxH', 0x81, 68) + called_name + calling_name
        return session_request
    
    def _parse_smb2_negotiate_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse SMB2 negotiate response."""
        try:
            if len(response) < 65:
                return None
            
            # Skip NetBIOS header (4 bytes)
            smb_data = response[4:]
            
            # Check SMB2 signature
            if smb_data[:4] != b'\xfeSMB':
                return None
            
            # Parse SMB2 header
            header_data = struct.unpack('<4sHHHHHHHIIIQ', smb_data[:64])
            
            # Parse negotiate response
            if len(smb_data) < 65:
                return None
            
            negotiate_data = smb_data[64:]
            if len(negotiate_data) < 36:
                return None
            
            structure_size, security_mode, dialect_revision = struct.unpack('<HHH', negotiate_data[:6])
            
            result = {
                'version': f'SMB {dialect_revision >> 8}.{dialect_revision & 0xFF}',
                'signing_enabled': bool(security_mode & 0x01),
                'signing_required': bool(security_mode & 0x02),
                'security_mode': security_mode
            }
            
            return result
            
        except Exception as e:
            logger.debug(f"Error parsing SMB2 response: {e}")
        
        return None
    
    def _parse_smb1_negotiate_response(self, response: bytes) -> Optional[Dict[str, Any]]:
        """Parse SMB1 negotiate response."""
        try:
            if len(response) < 39:  # Minimum SMB1 response size
                return None
            
            # Skip NetBIOS header (4 bytes)
            smb_data = response[4:]
            
            # Check SMB1 signature
            if smb_data[:4] != b'\xffSMB':
                return None
            
            # Parse SMB1 header
            if len(smb_data) < 32:
                return None
            
            header_data = struct.unpack('<4sBBBBBBHHHHHH', smb_data[:32])
            command, error_class, reserved1, error_code, flags, flags2 = header_data[1:7]
            
            # Check if negotiate was successful
            if command != 0x72 or error_class != 0:  # SMB_COM_NEGOTIATE
                return None
            
            # Parse negotiate response parameters
            if len(smb_data) < 39:
                return None
            
            word_count = smb_data[32]
            if word_count < 17:  # NT LM 0.12 response should have 17+ words
                return None
            
            # Extract security mode (word 4)
            security_mode = struct.unpack('<H', smb_data[41:43])[0]
            
            result = {
                'version': 'SMB 1.0 (NT LM 0.12)',
                'signing_enabled': bool(security_mode & 0x04),
                'signing_required': bool(security_mode & 0x08),
                'security_mode': security_mode
            }
            
            return result
            
        except Exception as e:
            logger.debug(f"Error parsing SMB1 response: {e}")
        
        return None
    
    def _check_smb_vulnerabilities(self, smb_result: Dict[str, Any]) -> List[str]:
        """Check for SMB vulnerabilities."""
        vulnerabilities = []
        
        # Check SMB signing
        if not smb_result.get('signing_required', True):
            vulnerabilities.append('SMB signing not required (relay attack risk)')
        
        # Check SMB version
        version = smb_result.get('version', '').lower()
        if 'smb 1' in version or 'nt lm' in version:
            vulnerabilities.append('SMBv1 enabled (deprecated and vulnerable)')
        
        return vulnerabilities
    
    def bulk_analyze(self, targets: List[str], max_workers: int = 10) -> List[Dict[str, Any]]:
        """Analyze multiple SMB targets concurrently."""
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_target = {
                executor.submit(self.analyze_smb_signing, host): host
                for host in targets
            }
            
            for future in concurrent.futures.as_completed(future_to_target):
                host = future_to_target[future]
                try:
                    result = future.result(timeout=30)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"SMB analysis failed for {host}: {e}")
        
        return results