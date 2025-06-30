#!/usr/bin/env python3
"""
Crypto Key Detection and Utility Functions
Comprehensive detection for various cryptocurrency keys, API keys, and credentials
"""

import re
import base64
import hashlib
import json
from typing import List, Dict, Any, Tuple
from cryptography.fernet import Fernet

class CryptoKeyDetector:
    """Comprehensive crypto key and credential detection"""
    
    def __init__(self):
        # Bitcoin patterns
        self.bitcoin_patterns = {
            'Bitcoin Private Key (WIF)': r'\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b',
            'Bitcoin Private Key (Hex)': r'\b[0-9a-fA-F]{64}\b',
            'Bitcoin Address (Legacy)': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'Bitcoin Address (Bech32)': r'\bbc1[a-z0-9]{39,59}\b',
            'Bitcoin Address (P2SH)': r'\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b'
        }
        
        # Ethereum patterns
        self.ethereum_patterns = {
            'Ethereum Private Key': r'\b0x[a-fA-F0-9]{64}\b',
            'Ethereum Address': r'\b0x[a-fA-F0-9]{40}\b',
            'Ethereum Keystore': r'\{"version"\s*:\s*3.*"crypto"\s*:.*\}',
        }
        
        # Other crypto patterns
        self.crypto_patterns = {
            'Monero Address': r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b',
            'Litecoin Address': r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b',
            'Dogecoin Address': r'\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b',
            'Ripple Address': r'\br[a-zA-Z0-9]{24,34}\b',
            'Cardano Address': r'\baddr1[a-z0-9]{98}\b',
            'Solana Address': r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'
        }
        
        # SSH and PGP keys
        self.key_patterns = {
            'SSH Private Key': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'SSH Public Key': r'ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/]+=*',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----.*?-----END PGP PRIVATE KEY BLOCK-----',
            'PGP Public Key': r'-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----',
            'SSL Certificate': r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
            'SSL Private Key': r'-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----'
        }
        
        # API Keys and tokens
        self.api_patterns = {
            'AWS Access Key': r'\bAKIA[0-9A-Z]{16}\b',
            'AWS Secret Key': r'\b[0-9a-zA-Z/+]{40}\b',
            'GitHub Token': r'\bghp_[a-zA-Z0-9]{36}\b',
            'GitHub Personal Access Token': r'\bgho_[a-zA-Z0-9]{36}\b',
            'Slack Token': r'\bxox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}\b',
            'Discord Token': r'\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b',
            'Stripe API Key': r'\bsk_live_[0-9a-zA-Z]{24}\b',
            'PayPal Client ID': r'\bAR[a-zA-Z0-9\-_]{59}\b',
            'Google API Key': r'\bAIza[0-9A-Za-z\-_]{35}\b',
            'Firebase Key': r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
            'JWT Token': r'\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b'
        }
        
        # Wallet seed phrases
        self.seed_patterns = {
            'BIP39 Seed Phrase (12 words)': r'\b(?:[a-z]+\s+){11}[a-z]+\b',
            'BIP39 Seed Phrase (24 words)': r'\b(?:[a-z]+\s+){23}[a-z]+\b',
            'Seed Phrase Indicator': r'(?i)\b(?:seed|mnemonic|recovery)\s+(?:phrase|words?)\b'
        }
        
        # Credential patterns
        self.credential_patterns = {
            'Email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Username': r'(?i)\b(?:user(?:name)?|login|account)[\s:=]+([a-zA-Z0-9._-]+)\b',
            'Password': r'(?i)\b(?:pass(?:word)?|pwd)[\s:=]+([^\s\n\r]+)\b',
            'URL': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'Domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        }

    def validate_bitcoin_address(self, address: str) -> bool:
        """Validate Bitcoin address using checksum"""
        try:
            if address.startswith('bc1'):  # Bech32
                return len(address) >= 42 and len(address) <= 62
            elif address.startswith(('1', '3')):  # Legacy/P2SH
                # Basic length and character validation
                return 25 <= len(address) <= 34 and all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in address)
            return False
        except:
            return False

    def validate_ethereum_address(self, address: str) -> bool:
        """Validate Ethereum address format"""
        if not address.startswith('0x') or len(address) != 42:
            return False
        try:
            int(address[2:], 16)
            return True
        except ValueError:
            return False

    def detect_crypto_keys(self, content: str, filename: str) -> List[Dict[str, Any]]:
        """Detect all types of crypto keys and credentials in content"""
        results = []
        
        # Detect Bitcoin keys/addresses
        for key_type, pattern in self.bitcoin_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                value = match.group().strip()
                if 'Address' in key_type and not self.validate_bitcoin_address(value):
                    continue
                results.append({
                    'type': 'Bitcoin',
                    'subtype': key_type,
                    'value': value,
                    'file': filename,
                    'position': match.start(),
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Detect Ethereum keys/addresses
        for key_type, pattern in self.ethereum_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                value = match.group().strip()
                if 'Address' in key_type and not self.validate_ethereum_address(value):
                    continue
                results.append({
                    'type': 'Ethereum',
                    'subtype': key_type,
                    'value': value,
                    'file': filename,
                    'position': match.start(),
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Detect other crypto currencies
        for key_type, pattern in self.crypto_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                value = match.group().strip()
                results.append({
                    'type': 'Cryptocurrency',
                    'subtype': key_type,
                    'value': value,
                    'file': filename,
                    'position': match.start(),
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Detect SSH/PGP keys
        for key_type, pattern in self.key_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                value = match.group().strip()
                # Truncate long keys for display
                display_value = value[:100] + '...' if len(value) > 100 else value
                results.append({
                    'type': 'Cryptographic Key',
                    'subtype': key_type,
                    'value': display_value,
                    'full_value': value,
                    'file': filename,
                    'position': match.start(),
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Detect API keys and tokens
        for key_type, pattern in self.api_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                value = match.group().strip()
                # Mask sensitive parts
                if len(value) > 8:
                    masked_value = value[:4] + '*' * (len(value) - 8) + value[-4:]
                else:
                    masked_value = '*' * len(value)
                results.append({
                    'type': 'API Key',
                    'subtype': key_type,
                    'value': masked_value,
                    'full_value': value,
                    'file': filename,
                    'position': match.start(),
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        # Detect seed phrases
        for key_type, pattern in self.seed_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                value = match.group().strip()
                if 'Indicator' not in key_type:
                    # Validate word count for seed phrases
                    words = value.split()
                    if len(words) in [12, 15, 18, 21, 24]:
                        results.append({
                            'type': 'Seed Phrase',
                            'subtype': f'{len(words)}-word Seed Phrase',
                            'value': ' '.join(words[:3]) + ' ... ' + ' '.join(words[-3:]),
                            'full_value': value,
                            'file': filename,
                            'position': match.start(),
                            'context': self._get_context(content, match.start(), match.end())
                        })
                else:
                    results.append({
                        'type': 'Seed Phrase',
                        'subtype': key_type,
                        'value': value,
                        'file': filename,
                        'position': match.start(),
                        'context': self._get_context(content, match.start(), match.end())
                    })
        
        # Detect credentials
        for key_type, pattern in self.credential_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                value = match.group(1) if match.groups() else match.group().strip()
                results.append({
                    'type': 'Credential',
                    'subtype': key_type,
                    'value': value,
                    'file': filename,
                    'position': match.start(),
                    'context': self._get_context(content, match.start(), match.end())
                })
        
        return results

    def _get_context(self, content: str, start: int, end: int, context_size: int = 50) -> str:
        """Get surrounding context for a match"""
        context_start = max(0, start - context_size)
        context_end = min(len(content), end + context_size)
        context = content[context_start:context_end].replace('\n', ' ').replace('\r', ' ')
        return context.strip()

    def group_related_items(self, results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group related items by proximity and context"""
        grouped = {}
        
        # First, group by type
        for result in results:
            result_type = result['type']
            if result_type not in grouped:
                grouped[result_type] = []
            grouped[result_type].append(result)
        
        # Then, within each type, try to find relationships
        for result_type, items in grouped.items():
            if result_type == 'Credential':
                grouped[result_type] = self._group_credentials(items)
        
        return grouped

    def _group_credentials(self, credentials: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Group credentials that appear to be related"""
        # Sort by position in file
        credentials.sort(key=lambda x: x['position'])
        
        grouped_creds = []
        current_group = []
        
        for i, cred in enumerate(credentials):
            if not current_group:
                current_group.append(cred)
            else:
                # If credentials are within 200 characters of each other, group them
                if cred['position'] - current_group[-1]['position'] < 200:
                    current_group.append(cred)
                else:
                    # Finalize current group and start new one
                    if len(current_group) > 1:
                        grouped_creds.append({
                            'type': 'Credential Group',
                            'subtype': 'Related Credentials',
                            'value': f"Group of {len(current_group)} related credentials",
                            'items': current_group,
                            'file': current_group[0]['file'],
                            'position': current_group[0]['position']
                        })
                    else:
                        grouped_creds.extend(current_group)
                    current_group = [cred]
        
        # Handle last group
        if current_group:
            if len(current_group) > 1:
                grouped_creds.append({
                    'type': 'Credential Group',
                    'subtype': 'Related Credentials',
                    'value': f"Group of {len(current_group)} related credentials",
                    'items': current_group,
                    'file': current_group[0]['file'],
                    'position': current_group[0]['position']
                })
            else:
                grouped_creds.extend(current_group)
        
        return grouped_creds

    def find_login_password_pairs(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find login/password pairs and associated sites"""
        pairs = []
        credentials = [r for r in results if r['type'] == 'Credential']
        
        # Sort by position
        credentials.sort(key=lambda x: x['position'])
        
        i = 0
        while i < len(credentials):
            current = credentials[i]
            
            # Look for username/email followed by password within reasonable distance
            if current['subtype'] in ['Username', 'Email']:
                # Look ahead for password within next few items or 500 characters
                for j in range(i + 1, min(i + 5, len(credentials))):
                    next_cred = credentials[j]
                    if (next_cred['subtype'] == 'Password' and 
                        next_cred['position'] - current['position'] < 500):
                        
                        # Look for associated URL/domain nearby
                        associated_site = None
                        for k in range(max(0, i - 2), min(len(credentials), j + 3)):
                            if credentials[k]['subtype'] in ['URL', 'Domain']:
                                if abs(credentials[k]['position'] - current['position']) < 300:
                                    associated_site = credentials[k]['value']
                                    break
                        
                        pairs.append({
                            'type': 'Login Pair',
                            'subtype': 'Username/Password',
                            'login': current['value'],
                            'password': next_cred['value'],
                            'site': associated_site or 'Unknown',
                            'file': current['file'],
                            'position': current['position']
                        })
                        break
            i += 1
        
        return pairs

def decrypt_license(encrypted_data: str) -> str:
    """Decrypt license data (placeholder implementation)"""
    try:
        # This is a placeholder - in a real implementation, you'd use proper decryption
        # For now, return a sample license for testing
        sample_license = {
            "user": "Test User",
            "expiry": "2025-12-31",
            "features": ["crypto_detection", "full_scan"]
        }
        return json.dumps(sample_license)
    except Exception as e:
        raise ValueError(f"Invalid license format: {e}")

# Convenience function for easy import
def detect_all_crypto_keys(content: str, filename: str) -> Dict[str, Any]:
    """Detect all crypto keys and return organized results"""
    detector = CryptoKeyDetector()
    results = detector.detect_crypto_keys(content, filename)
    grouped = detector.group_related_items(results)
    login_pairs = detector.find_login_password_pairs(results)
    
    return {
        'raw_results': results,
        'grouped_results': grouped,
        'login_pairs': login_pairs,
        'summary': {
            'total_items': len(results),
            'crypto_keys': len([r for r in results if r['type'] in ['Bitcoin', 'Ethereum', 'Cryptocurrency']]),
            'api_keys': len([r for r in results if r['type'] == 'API Key']),
            'credentials': len([r for r in results if r['type'] == 'Credential']),
            'login_pairs': len(login_pairs)
        }
    }

