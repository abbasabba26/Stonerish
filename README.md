# Enhanced Payment & Credential Scanner v2.0

A comprehensive PyQt6-based GUI application for scanning files and network traffic to detect payment information, credentials, and sensitive data. This enhanced version includes advanced network analysis capabilities and repository scanning features.

## 🚀 New Features in v2.0

### 🌐 Network Traffic Analysis
- **PCAP File Analysis**: Parse network capture files for credential extraction
- **Live Network Monitoring**: Real-time interface capture and analysis
- **Protocol-Specific Extraction**: Support for multiple authentication protocols
- **Advanced Credit Card Detection**: Extract payment information from network traffic

### 🔍 Repository Discovery
- **Credential Storage Scanning**: Find common credential storage locations
- **Configuration File Analysis**: Scan config files for sensitive information
- **Database Inspection**: Analyze SQLite databases for credential tables
- **Confidence Scoring**: High/Medium/Low confidence ratings for findings

### 📡 Supported Network Protocols
- **NTLM** (DCE-RPC, HTTP, SQL, LDAP)
- **Kerberos** (AS-REQ Pre-Auth etype 23)
- **HTTP Basic Authentication**
- **SNMP Community Strings**
- **Email Protocols** (POP, SMTP, IMAP)
- **FTP Credentials**
- **Telnet Authentication**

## 📋 Core Features

### File-Based Scanning
- **Multi-format Detection**: Credit cards, names, emails, phone numbers
- **Credit Card Validation**: Luhn algorithm validation
- **Batch Processing**: Multiple files or entire folders
- **Real-time Progress**: Progress bars and status updates
- **Export Results**: Multiple formats (TXT, JSON, CSV)

### Network Analysis
- **PCAP Support**: Analyze .pcap and .pcapng files
- **Live Capture**: Monitor network interfaces in real-time
- **Protocol Selection**: Choose specific protocols to analyze
- **Credential Extraction**: Usernames, passwords, hashes, tokens

### Repository Scanning
- **Common Locations**: Scan typical credential storage paths
- **File Type Detection**: Identify credential-related files
- **Content Analysis**: Extract credentials from various file formats
- **Pattern Matching**: Advanced regex patterns for credential detection

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges (for network monitoring)

### Dependencies Installation
```bash
pip install -r requirements.txt
```

### Required Packages
- `PyQt6>=6.4.0` - GUI framework
- `scapy>=2.5.0` - Network packet analysis
- `pyyaml>=6.0` - YAML configuration parsing
- `configparser>=5.3.0` - INI file parsing

## 🚀 Quick Start

### Basic Usage
```bash
python enhanced_scanner.py
```

### Command Line Network Analysis
```bash
# Analyze PCAP file
python network_analyzer.py sample.pcap

# Scan repository
python repository_scanner.py /path/to/scan
```

## 📖 Usage Guide

### 1. File Scanner Tab
- **Select Files/Folder**: Choose files to scan
- **Scan Options**: Select information types to detect
- **Start Scan**: Begin file analysis
- **Export Results**: Save findings to file

### 2. Network Scanner Tab
#### PCAP Analysis
1. Select PCAP file using "Browse" button
2. Choose protocols to analyze
3. Click "Analyze PCAP" to start
4. View results in Results tab

#### Live Monitoring
1. Select network interface from dropdown
2. Set packet count limit
3. Choose protocols to monitor
4. Click "Start Live Capture"
5. Use "Stop Capture" to end monitoring

### 3. Repository Scanner Tab
1. **Directory Selection**: Choose directory to scan
2. **Common Locations**: Enable to scan typical credential paths
3. **Start Scan**: Begin repository analysis
4. **View Results**: Check confidence-coded findings

### 4. Results Tab
- **File Results**: File-based scan findings
- **Network Results**: Network traffic credentials
- **Repository Results**: Credential repository discoveries
- **Export Options**: Save results in multiple formats

### 5. Settings Tab
- **File Extensions**: Customize file types to scan
- **Export Format**: Choose output format
- **About**: Version and feature information

## 🔧 Advanced Configuration

### Network Interface Setup
For live network monitoring, ensure:
- Administrator/root privileges
- Network interface access
- Firewall permissions for packet capture

### PCAP File Requirements
- Supported formats: .pcap, .pcapng
- Unencrypted traffic for credential extraction
- Sufficient packet data for analysis

### Repository Scanning Paths
Common credential locations scanned:
- `~/.ssh/` - SSH keys and configurations
- `~/.aws/` - AWS credentials
- `~/.config/` - Application configurations
- `config/`, `configs/` - Project configurations
- Database files (*.db, *.sqlite)
- Environment files (.env, .env.local)

## 📊 Supported Credential Types

### Network Credentials
- **Usernames/Passwords**: Plaintext authentication
- **NTLM Hashes**: NT and LM hash extraction
- **Kerberos Tickets**: Pre-authentication data
- **API Keys**: Various service tokens
- **Session Tokens**: Authentication tokens

### File-Based Information
- **Credit Cards**: Visa, MasterCard, AmEx, Discover
- **Personal Data**: Names, emails, phone numbers
- **Configuration Secrets**: API keys, passwords, tokens
- **Database Credentials**: Connection strings, passwords

### Repository Discoveries
- **SSH Keys**: Private key files
- **Cloud Credentials**: AWS, Google Cloud, Azure
- **Database Configs**: MySQL, PostgreSQL, SQLite
- **Application Secrets**: Environment variables, config files

## 🔒 Security Considerations

### Ethical Usage
- **Authorized Testing Only**: Use only on systems you own or have permission to test
- **Compliance**: Ensure compliance with local laws and regulations
- **Data Protection**: Handle discovered credentials responsibly
- **Secure Storage**: Protect scan results and exported data

### Network Monitoring
- **Privilege Requirements**: Network capture requires elevated privileges
- **Traffic Encryption**: Encrypted traffic cannot be analyzed
- **Legal Compliance**: Ensure network monitoring is legally permitted
- **Privacy Concerns**: Respect privacy and data protection laws

## 🐛 Troubleshooting

### Common Issues

#### Network Analysis Not Available
```
Error: Network analysis not available - install scapy for full functionality
```
**Solution**: Install scapy with `pip install scapy`

#### Permission Denied for Network Capture
```
Error: Permission denied accessing network interface
```
**Solution**: Run with administrator/root privileges

#### PCAP File Not Found
```
Error: Selected PCAP file does not exist
```
**Solution**: Verify file path and permissions

#### Repository Scanner Not Available
```
Error: Repository scanner module not available
```
**Solution**: Ensure all dependencies are installed

### Performance Tips
- **Large PCAP Files**: Process in smaller chunks for better performance
- **Network Monitoring**: Limit packet count for live capture
- **Repository Scanning**: Use specific directories instead of full system scans
- **File Scanning**: Filter file extensions to reduce processing time

## 📈 Export Formats

### Text Format
```
Network Scan Results
==================================================

Source: interface_eth0
Protocol: HTTP Basic Auth
Type: plaintext
Content: admin:password123
------------------------------
```

### JSON Format
```json
[
  {
    "source": "interface_eth0",
    "protocol": "HTTP Basic Auth",
    "type": "plaintext",
    "content": "admin:password123"
  }
]
```

### CSV Format
```csv
Source,Protocol,Type,Content
interface_eth0,HTTP Basic Auth,plaintext,admin:password123
```

## 🔄 Version History

### v2.0 (Current)
- ✅ Network traffic analysis (PCAP and live)
- ✅ Repository credential discovery
- ✅ Protocol-specific extraction
- ✅ Enhanced GUI with tabbed interface
- ✅ Multiple export formats
- ✅ Confidence scoring system

### v1.0 (Legacy)
- ✅ File-based payment information scanning
- ✅ Credit card validation
- ✅ Basic export functionality

## 📄 License

This project is provided as-is for educational and security auditing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please ensure all contributions maintain the security-focused nature of this tool and include appropriate documentation.

## ⚠️ Disclaimer

This tool is designed for legitimate security testing and compliance auditing. Users must ensure they have proper authorization before scanning any systems or networks. The developers are not responsible for any misuse of this software.
