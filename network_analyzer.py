#!/usr/bin/env python3
"""
Network Traffic Analyzer
Advanced network packet analysis for credential and sensitive data extraction
"""

import os
import sys
import re
import base64
import hashlib
import struct
import socket
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Network analysis features will be limited.")

@dataclass
class CredentialResult:
    """Structure for storing extracted credentials"""
    source: str  # File path or interface name
    protocol: str
    credential_type: str
    username: str = ""
    password: str = ""
    hash_value: str = ""
    domain: str = ""
    additional_info: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.additional_info is None:
            self.additional_info = {}

class NetworkAnalyzer:
    """Main network traffic analyzer class"""
    
    def __init__(self):
        self.results = []
        self.supported_protocols = [
            'HTTP Basic Auth', 'NTLM', 'Kerberos', 'FTP', 'SMTP', 
            'POP3', 'IMAP', 'SNMP', 'Telnet', 'SSH'
        ]
        
    def analyze_pcap_file(self, pcap_path: str, protocols: List[str] = None) -> List[CredentialResult]:
        """Analyze a PCAP file for credentials"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for PCAP analysis")
            
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
            
        results = []
        protocols = protocols or self.supported_protocols
        
        try:
            packets = rdpcap(pcap_path)
            print(f"Analyzing {len(packets)} packets from {pcap_path}")
            
            for packet in packets:
                # Analyze each protocol
                if 'HTTP Basic Auth' in protocols:
                    results.extend(self._extract_http_basic_auth(packet, pcap_path))
                if 'NTLM' in protocols:
                    results.extend(self._extract_ntlm_credentials(packet, pcap_path))
                if 'Kerberos' in protocols:
                    results.extend(self._extract_kerberos_credentials(packet, pcap_path))
                if 'FTP' in protocols:
                    results.extend(self._extract_ftp_credentials(packet, pcap_path))
                if 'SMTP' in protocols:
                    results.extend(self._extract_smtp_credentials(packet, pcap_path))
                if 'POP3' in protocols:
                    results.extend(self._extract_pop3_credentials(packet, pcap_path))
                if 'IMAP' in protocols:
                    results.extend(self._extract_imap_credentials(packet, pcap_path))
                if 'SNMP' in protocols:
                    results.extend(self._extract_snmp_credentials(packet, pcap_path))
                if 'Telnet' in protocols:
                    results.extend(self._extract_telnet_credentials(packet, pcap_path))
                    
        except Exception as e:
            print(f"Error analyzing PCAP file: {e}")
            
        self.results.extend(results)
        return results
    
    def start_live_capture(self, interface: str, protocols: List[str] = None, 
                          packet_count: int = 0) -> None:
        """Start live packet capture on specified interface"""
        if not SCAPY_AVAILABLE:
            raise ImportError("Scapy is required for live capture")
            
        protocols = protocols or self.supported_protocols
        
        def packet_handler(packet):
            results = []
            if 'HTTP Basic Auth' in protocols:
                results.extend(self._extract_http_basic_auth(packet, interface))
            if 'NTLM' in protocols:
                results.extend(self._extract_ntlm_credentials(packet, interface))
            if 'Kerberos' in protocols:
                results.extend(self._extract_kerberos_credentials(packet, interface))
            if 'FTP' in protocols:
                results.extend(self._extract_ftp_credentials(packet, interface))
            if 'SMTP' in protocols:
                results.extend(self._extract_smtp_credentials(packet, interface))
            if 'POP3' in protocols:
                results.extend(self._extract_pop3_credentials(packet, interface))
            if 'IMAP' in protocols:
                results.extend(self._extract_imap_credentials(packet, interface))
            if 'SNMP' in protocols:
                results.extend(self._extract_snmp_credentials(packet, interface))
            if 'Telnet' in protocols:
                results.extend(self._extract_telnet_credentials(packet, interface))
                
            self.results.extend(results)
            
        try:
            sniff(iface=interface, prn=packet_handler, count=packet_count)
        except Exception as e:
            print(f"Error during live capture: {e}")
    
    def get_network_interfaces(self) -> List[str]:
        """Get list of available network interfaces"""
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            return get_if_list()
        except:
            return []
    
    def _extract_http_basic_auth(self, packet, source: str) -> List[CredentialResult]:
        """Extract HTTP Basic Authentication credentials"""
        results = []
        
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            if hasattr(http_layer, 'Authorization'):
                auth_header = http_layer.Authorization.decode('utf-8', errors='ignore')
                if auth_header.startswith('Basic '):
                    try:
                        encoded_creds = auth_header[6:]  # Remove 'Basic '
                        decoded_creds = base64.b64decode(encoded_creds).decode('utf-8')
                        if ':' in decoded_creds:
                            username, password = decoded_creds.split(':', 1)
                            results.append(CredentialResult(
                                source=source,
                                protocol='HTTP Basic Auth',
                                credential_type='plaintext',
                                username=username,
                                password=password,
                                additional_info={
                                    'url': http_layer.Host.decode() + http_layer.Path.decode() if hasattr(http_layer, 'Host') else '',
                                    'user_agent': http_layer.User_Agent.decode() if hasattr(http_layer, 'User_Agent') else ''
                                }
                            ))
                    except Exception as e:
                        print(f"Error decoding HTTP Basic Auth: {e}")
        
        return results
    
    def _extract_ntlm_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract NTLM authentication data"""
        results = []
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            
            # Look for NTLM signatures
            if b'NTLMSSP' in payload:
                try:
                    # NTLM Type 1 Message (Negotiate)
                    if b'NTLMSSP\x00\x01\x00\x00\x00' in payload:
                        results.append(CredentialResult(
                            source=source,
                            protocol='NTLM',
                            credential_type='negotiate',
                            additional_info={'message_type': 'Type 1 - Negotiate'}
                        ))
                    
                    # NTLM Type 2 Message (Challenge)
                    elif b'NTLMSSP\x00\x02\x00\x00\x00' in payload:
                        challenge_start = payload.find(b'NTLMSSP\x00\x02\x00\x00\x00')
                        if challenge_start != -1:
                            challenge_data = payload[challenge_start:challenge_start+64]
                            results.append(CredentialResult(
                                source=source,
                                protocol='NTLM',
                                credential_type='challenge',
                                additional_info={
                                    'message_type': 'Type 2 - Challenge',
                                    'challenge': challenge_data.hex()
                                }
                            ))
                    
                    # NTLM Type 3 Message (Authentication)
                    elif b'NTLMSSP\x00\x03\x00\x00\x00' in payload:
                        auth_start = payload.find(b'NTLMSSP\x00\x03\x00\x00\x00')
                        if auth_start != -1:
                            # Parse NTLM Type 3 message for username, domain, and hashes
                            username, domain, nt_hash, lm_hash = self._parse_ntlm_type3(payload[auth_start:])
                            if username:
                                results.append(CredentialResult(
                                    source=source,
                                    protocol='NTLM',
                                    credential_type='hash',
                                    username=username,
                                    domain=domain,
                                    hash_value=nt_hash,
                                    additional_info={
                                        'message_type': 'Type 3 - Authentication',
                                        'lm_hash': lm_hash,
                                        'nt_hash': nt_hash
                                    }
                                ))
                
                except Exception as e:
                    print(f"Error parsing NTLM: {e}")
        
        return results
    
    def _parse_ntlm_type3(self, data: bytes) -> Tuple[str, str, str, str]:
        """Parse NTLM Type 3 authentication message"""
        try:
            if len(data) < 64:
                return "", "", "", ""
                
            # NTLM Type 3 structure parsing
            # Skip signature and message type (12 bytes)
            offset = 12
            
            # LM Response
            lm_len = struct.unpack('<H', data[offset:offset+2])[0]
            lm_offset = struct.unpack('<I', data[offset+4:offset+8])[0]
            offset += 8
            
            # NT Response  
            nt_len = struct.unpack('<H', data[offset:offset+2])[0]
            nt_offset = struct.unpack('<I', data[offset+4:offset+8])[0]
            offset += 8
            
            # Domain
            domain_len = struct.unpack('<H', data[offset:offset+2])[0]
            domain_offset = struct.unpack('<I', data[offset+4:offset+8])[0]
            offset += 8
            
            # Username
            user_len = struct.unpack('<H', data[offset:offset+2])[0]
            user_offset = struct.unpack('<I', data[offset+4:offset+8])[0]
            
            # Extract strings
            username = ""
            domain = ""
            lm_hash = ""
            nt_hash = ""
            
            if user_len > 0 and user_offset < len(data):
                username = data[user_offset:user_offset+user_len].decode('utf-16le', errors='ignore')
                
            if domain_len > 0 and domain_offset < len(data):
                domain = data[domain_offset:domain_offset+domain_len].decode('utf-16le', errors='ignore')
                
            if lm_len > 0 and lm_offset < len(data):
                lm_hash = data[lm_offset:lm_offset+lm_len].hex()
                
            if nt_len > 0 and nt_offset < len(data):
                nt_hash = data[nt_offset:nt_offset+nt_len].hex()
            
            return username, domain, nt_hash, lm_hash
            
        except Exception as e:
            print(f"Error parsing NTLM Type 3: {e}")
            return "", "", "", ""
    
    def _extract_kerberos_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract Kerberos authentication data"""
        results = []
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw])
            
            # Look for Kerberos AS-REQ with pre-authentication
            if b'\x6a' in payload:  # Kerberos tag
                try:
                    # Look for etype 23 (RC4-HMAC) pre-auth data
                    if b'\x17' in payload:  # etype 23
                        # Extract username from principal name
                        username = self._extract_kerberos_principal(payload)
                        if username:
                            results.append(CredentialResult(
                                source=source,
                                protocol='Kerberos',
                                credential_type='pre-auth',
                                username=username,
                                additional_info={
                                    'etype': '23 (RC4-HMAC)',
                                    'message_type': 'AS-REQ'
                                }
                            ))
                
                except Exception as e:
                    print(f"Error parsing Kerberos: {e}")
        
        return results
    
    def _extract_kerberos_principal(self, data: bytes) -> str:
        """Extract principal name from Kerberos data"""
        try:
            # Simple extraction - look for printable strings that could be usernames
            strings = re.findall(b'[a-zA-Z0-9._-]{3,}', data)
            for s in strings:
                decoded = s.decode('ascii', errors='ignore')
                if len(decoded) > 2 and not decoded.isdigit():
                    return decoded
        except:
            pass
        return ""
    
    def _extract_ftp_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract FTP credentials"""
        results = []
        
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            
            # FTP USER command
            user_match = re.search(r'USER\s+([^\r\n]+)', payload, re.IGNORECASE)
            if user_match:
                username = user_match.group(1).strip()
                results.append(CredentialResult(
                    source=source,
                    protocol='FTP',
                    credential_type='username',
                    username=username,
                    additional_info={'command': 'USER'}
                ))
            
            # FTP PASS command
            pass_match = re.search(r'PASS\s+([^\r\n]+)', payload, re.IGNORECASE)
            if pass_match:
                password = pass_match.group(1).strip()
                results.append(CredentialResult(
                    source=source,
                    protocol='FTP',
                    credential_type='password',
                    password=password,
                    additional_info={'command': 'PASS'}
                ))
        
        return results
    
    def _extract_smtp_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract SMTP credentials"""
        results = []
        
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            
            # SMTP AUTH LOGIN
            if 'AUTH LOGIN' in payload.upper():
                # Look for base64 encoded credentials in subsequent packets
                b64_pattern = r'([A-Za-z0-9+/]{4,}={0,2})'
                matches = re.findall(b64_pattern, payload)
                for match in matches:
                    try:
                        decoded = base64.b64decode(match).decode('utf-8')
                        if '@' in decoded:  # Likely email
                            results.append(CredentialResult(
                                source=source,
                                protocol='SMTP',
                                credential_type='username',
                                username=decoded,
                                additional_info={'auth_method': 'LOGIN'}
                            ))
                        elif len(decoded) > 3:  # Likely password
                            results.append(CredentialResult(
                                source=source,
                                protocol='SMTP',
                                credential_type='password',
                                password=decoded,
                                additional_info={'auth_method': 'LOGIN'}
                            ))
                    except:
                        pass
        
        return results
    
    def _extract_pop3_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract POP3 credentials"""
        results = []
        
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            
            # POP3 USER command
            user_match = re.search(r'USER\s+([^\r\n]+)', payload, re.IGNORECASE)
            if user_match:
                username = user_match.group(1).strip()
                results.append(CredentialResult(
                    source=source,
                    protocol='POP3',
                    credential_type='username',
                    username=username
                ))
            
            # POP3 PASS command
            pass_match = re.search(r'PASS\s+([^\r\n]+)', payload, re.IGNORECASE)
            if pass_match:
                password = pass_match.group(1).strip()
                results.append(CredentialResult(
                    source=source,
                    protocol='POP3',
                    credential_type='password',
                    password=password
                ))
        
        return results
    
    def _extract_imap_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract IMAP credentials"""
        results = []
        
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            
            # IMAP LOGIN command
            login_match = re.search(r'LOGIN\s+([^\s]+)\s+([^\r\n]+)', payload, re.IGNORECASE)
            if login_match:
                username = login_match.group(1).strip('"')
                password = login_match.group(2).strip('"')
                results.append(CredentialResult(
                    source=source,
                    protocol='IMAP',
                    credential_type='plaintext',
                    username=username,
                    password=password
                ))
        
        return results
    
    def _extract_snmp_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract SNMP community strings"""
        results = []
        
        if packet.haslayer(Raw) and packet.haslayer(UDP):
            payload = bytes(packet[Raw])
            
            # SNMP community string extraction (simplified)
            try:
                # Look for SNMP version and community string patterns
                if len(payload) > 10:
                    # Simple heuristic for SNMP community strings
                    strings = re.findall(b'[a-zA-Z0-9]{4,20}', payload)
                    for s in strings:
                        community = s.decode('ascii', errors='ignore')
                        if community not in ['public', 'private'] and len(community) > 3:
                            results.append(CredentialResult(
                                source=source,
                                protocol='SNMP',
                                credential_type='community_string',
                                password=community
                            ))
            except:
                pass
        
        return results
    
    def _extract_telnet_credentials(self, packet, source: str) -> List[CredentialResult]:
        """Extract Telnet credentials"""
        results = []
        
        if packet.haslayer(Raw) and packet.haslayer(TCP):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            
            # Look for login prompts and responses
            if 'login:' in payload.lower() or 'username:' in payload.lower():
                # Extract potential username
                lines = payload.split('\n')
                for line in lines:
                    if 'login:' in line.lower() or 'username:' in line.lower():
                        parts = line.split(':')
                        if len(parts) > 1:
                            username = parts[1].strip()
                            if username and len(username) > 1:
                                results.append(CredentialResult(
                                    source=source,
                                    protocol='Telnet',
                                    credential_type='username',
                                    username=username
                                ))
            
            if 'password:' in payload.lower():
                # Note: Telnet passwords are usually not visible in clear text
                results.append(CredentialResult(
                    source=source,
                    protocol='Telnet',
                    credential_type='password_prompt',
                    additional_info={'note': 'Password prompt detected'}
                ))
        
        return results
    
    def extract_credit_cards_from_traffic(self, packet, source: str) -> List[CredentialResult]:
        """Extract credit card information from network traffic"""
        results = []
        
        if packet.haslayer(Raw):
            payload = bytes(packet[Raw]).decode('utf-8', errors='ignore')
            
            # Credit card patterns
            card_patterns = {
                'Visa': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
                'MasterCard': r'\b5[1-5][0-9]{14}\b',
                'American Express': r'\b3[47][0-9]{13}\b',
                'Discover': r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'
            }
            
            for card_type, pattern in card_patterns.items():
                matches = re.finditer(pattern, payload)
                for match in matches:
                    card_number = match.group()
                    if self._luhn_check(card_number):
                        results.append(CredentialResult(
                            source=source,
                            protocol='Network Traffic',
                            credential_type='credit_card',
                            additional_info={
                                'card_type': card_type,
                                'card_number': card_number,
                                'masked_number': card_number[:4] + '*' * (len(card_number) - 8) + card_number[-4:]
                            }
                        ))
        
        return results
    
    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        return checksum % 10 == 0
    
    def get_results(self) -> List[CredentialResult]:
        """Get all extracted results"""
        return self.results
    
    def clear_results(self):
        """Clear all results"""
        self.results.clear()
    
    def export_results(self, filename: str, format: str = 'txt') -> bool:
        """Export results to file"""
        try:
            if format.lower() == 'json':
                import json
                data = []
                for result in self.results:
                    data.append({
                        'source': result.source,
                        'protocol': result.protocol,
                        'credential_type': result.credential_type,
                        'username': result.username,
                        'password': result.password,
                        'hash_value': result.hash_value,
                        'domain': result.domain,
                        'additional_info': result.additional_info,
                        'timestamp': result.timestamp.isoformat()
                    })
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write("Network Traffic Analysis Results\n")
                    f.write("=" * 50 + "\n\n")
                    for result in self.results:
                        f.write(f"Source: {result.source}\n")
                        f.write(f"Protocol: {result.protocol}\n")
                        f.write(f"Type: {result.credential_type}\n")
                        if result.username:
                            f.write(f"Username: {result.username}\n")
                        if result.password:
                            f.write(f"Password: {result.password}\n")
                        if result.hash_value:
                            f.write(f"Hash: {result.hash_value}\n")
                        if result.domain:
                            f.write(f"Domain: {result.domain}\n")
                        if result.additional_info:
                            f.write(f"Additional Info: {result.additional_info}\n")
                        f.write(f"Timestamp: {result.timestamp}\n")
                        f.write("-" * 30 + "\n")
            return True
        except Exception as e:
            print(f"Error exporting results: {e}")
            return False

if __name__ == "__main__":
    # Test the network analyzer
    analyzer = NetworkAnalyzer()
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        if os.path.exists(pcap_file):
            results = analyzer.analyze_pcap_file(pcap_file)
            print(f"Found {len(results)} credential entries")
            for result in results:
                print(f"{result.protocol}: {result.username} / {result.credential_type}")
        else:
            print(f"PCAP file not found: {pcap_file}")
    else:
        print("Network Analyzer - Usage: python network_analyzer.py <pcap_file>")
        interfaces = analyzer.get_network_interfaces()
        if interfaces:
            print(f"Available interfaces: {', '.join(interfaces)}")

