#!/usr/bin/env python3
"""
Repository Scanner
Discovers common credential storage locations and configuration files
"""

import os
import re
import json
import configparser
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class RepositoryResult:
    """Structure for repository scan results"""
    file_path: str
    repository_type: str
    credential_type: str
    content: str
    confidence: str  # high, medium, low
    additional_info: Dict[str, Any] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.additional_info is None:
            self.additional_info = {}

class RepositoryScanner:
    """Scanner for credential repositories and configuration files"""
    
    def __init__(self):
        self.results = []
        
        # Common credential file patterns
        self.credential_files = {
            # Configuration files
            '.env': 'Environment Variables',
            '.env.local': 'Environment Variables',
            '.env.production': 'Environment Variables',
            'config.json': 'JSON Configuration',
            'config.yaml': 'YAML Configuration',
            'config.yml': 'YAML Configuration',
            'settings.json': 'Settings File',
            'appsettings.json': '.NET Configuration',
            'web.config': 'Web Configuration',
            'app.config': 'Application Configuration',
            
            # Database files
            'credentials.db': 'SQLite Database',
            'users.db': 'SQLite Database',
            'auth.db': 'SQLite Database',
            
            # SSH and certificates
            'id_rsa': 'SSH Private Key',
            'id_dsa': 'SSH Private Key',
            'id_ecdsa': 'SSH Private Key',
            'id_ed25519': 'SSH Private Key',
            'known_hosts': 'SSH Known Hosts',
            'authorized_keys': 'SSH Authorized Keys',
            
            # Cloud and service configs
            'credentials': 'AWS Credentials',
            'config': 'AWS Config',
            '.boto': 'Boto Configuration',
            '.s3cfg': 'S3 Configuration',
            'gcloud.json': 'Google Cloud Credentials',
            'service-account.json': 'Service Account Key',
            
            # Application specific
            '.netrc': 'Network Resource Configuration',
            '.pgpass': 'PostgreSQL Password File',
            '.my.cnf': 'MySQL Configuration',
            'wp-config.php': 'WordPress Configuration',
            'settings.py': 'Django Settings',
            'local_settings.py': 'Django Local Settings',
            
            # Version control
            '.git-credentials': 'Git Credentials',
            '.gitconfig': 'Git Configuration',
            
            # Browser and application data
            'Login Data': 'Chrome Passwords',
            'key4.db': 'Firefox Passwords',
            'logins.json': 'Firefox Passwords',
        }
        
        # Directory patterns to search
        self.search_directories = [
            '.ssh',
            '.aws',
            '.config',
            'config',
            'configs',
            'credentials',
            'keys',
            'certs',
            'certificates',
            '.git',
            'AppData/Local/Google/Chrome/User Data/Default',
            'AppData/Roaming/Mozilla/Firefox/Profiles',
            '.mozilla/firefox',
            '.chrome',
            'Library/Application Support/Google/Chrome/Default',
            'Library/Application Support/Firefox/Profiles',
        ]
        
        # Credential patterns in files
        self.credential_patterns = {
            'API Key': [
                r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'(?i)apikey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            ],
            'Secret Key': [
                r'(?i)secret[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'(?i)secretkey["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            ],
            'Access Token': [
                r'(?i)access[_-]?token["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
                r'(?i)accesstoken["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_-]{20,})["\']?',
            ],
            'Password': [
                r'(?i)password["\']?\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                r'(?i)passwd["\']?\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
                r'(?i)pwd["\']?\s*[:=]\s*["\']?([^"\'\s]{4,})["\']?',
            ],
            'Database URL': [
                r'(?i)database[_-]?url["\']?\s*[:=]\s*["\']?([^"\'\s]+://[^"\'\s]+)["\']?',
                r'(?i)db[_-]?url["\']?\s*[:=]\s*["\']?([^"\'\s]+://[^"\'\s]+)["\']?',
            ],
            'Connection String': [
                r'(?i)connection[_-]?string["\']?\s*[:=]\s*["\']?([^"\']+)["\']?',
                r'(?i)connectionstring["\']?\s*[:=]\s*["\']?([^"\']+)["\']?',
            ],
            'Private Key': [
                r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
                r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----',
                r'-----BEGIN\s+EC\s+PRIVATE\s+KEY-----',
            ],
            'AWS Access Key': [
                r'(?i)aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']?([A-Z0-9]{20})["\']?',
                r'AKIA[0-9A-Z]{16}',
            ],
            'AWS Secret Key': [
                r'(?i)aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?',
            ],
            'Google API Key': [
                r'AIza[0-9A-Za-z_-]{35}',
            ],
            'GitHub Token': [
                r'ghp_[0-9A-Za-z]{36}',
                r'gho_[0-9A-Za-z]{36}',
                r'ghu_[0-9A-Za-z]{36}',
                r'ghs_[0-9A-Za-z]{36}',
                r'ghr_[0-9A-Za-z]{36}',
            ],
            'JWT Token': [
                r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            ],
        }
    
    def scan_directory(self, directory_path: str, recursive: bool = True) -> List[RepositoryResult]:
        """Scan directory for credential repositories"""
        results = []
        
        if not os.path.exists(directory_path):
            return results
        
        try:
            if recursive:
                for root, dirs, files in os.walk(directory_path):
                    # Skip hidden directories except specific ones we want
                    dirs[:] = [d for d in dirs if not d.startswith('.') or d in ['.ssh', '.aws', '.config', '.git']]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        results.extend(self._scan_file(file_path))
            else:
                for item in os.listdir(directory_path):
                    item_path = os.path.join(directory_path, item)
                    if os.path.isfile(item_path):
                        results.extend(self._scan_file(item_path))
        
        except PermissionError:
            print(f"Permission denied accessing: {directory_path}")
        except Exception as e:
            print(f"Error scanning directory {directory_path}: {e}")
        
        self.results.extend(results)
        return results
    
    def scan_common_locations(self) -> List[RepositoryResult]:
        """Scan common credential storage locations"""
        results = []
        home_dir = Path.home()
        
        # Scan home directory subdirectories
        for subdir in self.search_directories:
            search_path = home_dir / subdir
            if search_path.exists():
                results.extend(self.scan_directory(str(search_path)))
        
        # Scan current directory
        results.extend(self.scan_directory('.', recursive=False))
        
        # Scan system locations (if accessible)
        system_locations = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/ssh/ssh_config',
            '/etc/mysql/my.cnf',
            '/etc/postgresql',
            'C:\\Windows\\System32\\config',
            'C:\\ProgramData',
        ]
        
        for location in system_locations:
            if os.path.exists(location):
                if os.path.isfile(location):
                    results.extend(self._scan_file(location))
                else:
                    results.extend(self.scan_directory(location, recursive=False))
        
        return results
    
    def _scan_file(self, file_path: str) -> List[RepositoryResult]:
        """Scan individual file for credentials"""
        results = []
        
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Skip very large files
            if file_size > 10 * 1024 * 1024:  # 10MB
                return results
            
            # Check if it's a known credential file
            if file_name in self.credential_files:
                repo_type = self.credential_files[file_name]
                results.append(RepositoryResult(
                    file_path=file_path,
                    repository_type=repo_type,
                    credential_type='file_location',
                    content=f"Known credential file: {file_name}",
                    confidence='high',
                    additional_info={'file_size': file_size}
                ))
            
            # Scan file content for credential patterns
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    results.extend(self._scan_content(file_path, content))
            except (UnicodeDecodeError, PermissionError):
                # Try binary mode for special files
                try:
                    with open(file_path, 'rb') as f:
                        binary_content = f.read()
                        # Look for specific binary patterns
                        if b'-----BEGIN' in binary_content and b'PRIVATE KEY-----' in binary_content:
                            results.append(RepositoryResult(
                                file_path=file_path,
                                repository_type='Private Key File',
                                credential_type='private_key',
                                content='Binary private key detected',
                                confidence='high'
                            ))
                except:
                    pass
            
            # Special handling for specific file types
            if file_name.endswith('.db') or file_name.endswith('.sqlite'):
                results.extend(self._scan_sqlite_database(file_path))
            elif file_name.endswith('.json'):
                results.extend(self._scan_json_file(file_path))
            elif file_name.endswith(('.yaml', '.yml')):
                results.extend(self._scan_yaml_file(file_path))
            elif file_name.endswith('.ini') or file_name.endswith('.cfg'):
                results.extend(self._scan_ini_file(file_path))
        
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
        
        return results
    
    def _scan_content(self, file_path: str, content: str) -> List[RepositoryResult]:
        """Scan file content for credential patterns"""
        results = []
        
        for cred_type, patterns in self.credential_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    matched_text = match.group()
                    confidence = self._assess_confidence(cred_type, matched_text, content)
                    
                    results.append(RepositoryResult(
                        file_path=file_path,
                        repository_type='Text File',
                        credential_type=cred_type,
                        content=matched_text[:100] + '...' if len(matched_text) > 100 else matched_text,
                        confidence=confidence,
                        additional_info={
                            'pattern': pattern,
                            'line_number': content[:match.start()].count('\n') + 1
                        }
                    ))
        
        return results
    
    def _scan_sqlite_database(self, file_path: str) -> List[RepositoryResult]:
        """Scan SQLite database for credential tables"""
        results = []
        
        try:
            conn = sqlite3.connect(file_path)
            cursor = conn.cursor()
            
            # Get table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            
            for table in tables:
                table_name = table[0]
                
                # Check for credential-related table names
                if any(keyword in table_name.lower() for keyword in 
                       ['user', 'login', 'auth', 'credential', 'password', 'account']):
                    
                    # Get column names
                    cursor.execute(f"PRAGMA table_info({table_name});")
                    columns = cursor.fetchall()
                    
                    credential_columns = []
                    for col in columns:
                        col_name = col[1].lower()
                        if any(keyword in col_name for keyword in 
                               ['password', 'pass', 'pwd', 'hash', 'token', 'key', 'secret']):
                            credential_columns.append(col[1])
                    
                    if credential_columns:
                        results.append(RepositoryResult(
                            file_path=file_path,
                            repository_type='SQLite Database',
                            credential_type='database_table',
                            content=f"Table: {table_name}, Credential columns: {', '.join(credential_columns)}",
                            confidence='high',
                            additional_info={
                                'table_name': table_name,
                                'credential_columns': credential_columns
                            }
                        ))
            
            conn.close()
        
        except Exception as e:
            print(f"Error scanning SQLite database {file_path}: {e}")
        
        return results
    
    def _scan_json_file(self, file_path: str) -> List[RepositoryResult]:
        """Scan JSON file for credential structures"""
        results = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                results.extend(self._scan_json_object(file_path, data, ''))
        
        except Exception as e:
            print(f"Error scanning JSON file {file_path}: {e}")
        
        return results
    
    def _scan_json_object(self, file_path: str, obj: Any, path: str) -> List[RepositoryResult]:
        """Recursively scan JSON object for credentials"""
        results = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if key suggests credentials
                key_lower = key.lower()
                if any(keyword in key_lower for keyword in 
                       ['password', 'secret', 'key', 'token', 'credential', 'auth']):
                    
                    results.append(RepositoryResult(
                        file_path=file_path,
                        repository_type='JSON Configuration',
                        credential_type='json_credential',
                        content=f"{current_path}: {str(value)[:50]}{'...' if len(str(value)) > 50 else ''}",
                        confidence='medium',
                        additional_info={'json_path': current_path}
                    ))
                
                # Recurse into nested objects
                if isinstance(value, (dict, list)):
                    results.extend(self._scan_json_object(file_path, value, current_path))
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                current_path = f"{path}[{i}]"
                if isinstance(item, (dict, list)):
                    results.extend(self._scan_json_object(file_path, item, current_path))
        
        return results
    
    def _scan_yaml_file(self, file_path: str) -> List[RepositoryResult]:
        """Scan YAML file for credentials"""
        results = []
        
        try:
            import yaml
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if data:
                    results.extend(self._scan_json_object(file_path, data, ''))
        except ImportError:
            print("PyYAML not available, skipping YAML file analysis")
        except Exception as e:
            print(f"Error scanning YAML file {file_path}: {e}")
        
        return results
    
    def _scan_ini_file(self, file_path: str) -> List[RepositoryResult]:
        """Scan INI/CFG file for credentials"""
        results = []
        
        try:
            config = configparser.ConfigParser()
            config.read(file_path)
            
            for section_name in config.sections():
                section = config[section_name]
                for key, value in section.items():
                    key_lower = key.lower()
                    if any(keyword in key_lower for keyword in 
                           ['password', 'secret', 'key', 'token', 'credential']):
                        
                        results.append(RepositoryResult(
                            file_path=file_path,
                            repository_type='INI Configuration',
                            credential_type='ini_credential',
                            content=f"[{section_name}] {key} = {value[:30]}{'...' if len(value) > 30 else ''}",
                            confidence='medium',
                            additional_info={
                                'section': section_name,
                                'key': key
                            }
                        ))
        
        except Exception as e:
            print(f"Error scanning INI file {file_path}: {e}")
        
        return results
    
    def _assess_confidence(self, cred_type: str, matched_text: str, full_content: str) -> str:
        """Assess confidence level of credential match"""
        # High confidence patterns
        if cred_type in ['Private Key', 'AWS Access Key', 'GitHub Token', 'Google API Key']:
            return 'high'
        
        # Check for common false positives
        false_positives = [
            'password', 'secret', 'key', 'token', 'example', 'test', 'demo',
            'placeholder', 'your_password', 'your_key', 'your_token'
        ]
        
        if any(fp in matched_text.lower() for fp in false_positives):
            return 'low'
        
        # Check context for additional confidence
        context_keywords = ['production', 'prod', 'live', 'real', 'actual']
        if any(keyword in full_content.lower() for keyword in context_keywords):
            return 'high'
        
        return 'medium'
    
    def get_results(self) -> List[RepositoryResult]:
        """Get all scan results"""
        return self.results
    
    def clear_results(self):
        """Clear all results"""
        self.results.clear()
    
    def export_results(self, filename: str, format: str = 'txt') -> bool:
        """Export results to file"""
        try:
            if format.lower() == 'json':
                data = []
                for result in self.results:
                    data.append({
                        'file_path': result.file_path,
                        'repository_type': result.repository_type,
                        'credential_type': result.credential_type,
                        'content': result.content,
                        'confidence': result.confidence,
                        'additional_info': result.additional_info,
                        'timestamp': result.timestamp.isoformat()
                    })
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write("Repository Scan Results\n")
                    f.write("=" * 50 + "\n\n")
                    
                    # Group by confidence level
                    high_conf = [r for r in self.results if r.confidence == 'high']
                    medium_conf = [r for r in self.results if r.confidence == 'medium']
                    low_conf = [r for r in self.results if r.confidence == 'low']
                    
                    for conf_level, results in [('HIGH', high_conf), ('MEDIUM', medium_conf), ('LOW', low_conf)]:
                        if results:
                            f.write(f"\n{conf_level} CONFIDENCE RESULTS:\n")
                            f.write("-" * 30 + "\n")
                            for result in results:
                                f.write(f"File: {result.file_path}\n")
                                f.write(f"Type: {result.repository_type}\n")
                                f.write(f"Credential: {result.credential_type}\n")
                                f.write(f"Content: {result.content}\n")
                                if result.additional_info:
                                    f.write(f"Info: {result.additional_info}\n")
                                f.write(f"Timestamp: {result.timestamp}\n")
                                f.write("-" * 20 + "\n")
            return True
        except Exception as e:
            print(f"Error exporting results: {e}")
            return False

if __name__ == "__main__":
    # Test the repository scanner
    scanner = RepositoryScanner()
    
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
        results = scanner.scan_directory(scan_path)
        print(f"Found {len(results)} potential credential repositories")
        for result in results:
            print(f"{result.confidence.upper()}: {result.file_path} - {result.credential_type}")
    else:
        print("Repository Scanner - Usage: python repository_scanner.py <directory_path>")
        print("Scanning common locations...")
        results = scanner.scan_common_locations()
        print(f"Found {len(results)} potential credential repositories")

