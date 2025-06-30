# Enhanced Security Scanner

A comprehensive PyQt6-based GUI application for scanning files and detecting sensitive information including payment data, cryptocurrency keys, API tokens, and credentials.

## Features

### 🔍 **Comprehensive Detection**
- **Payment Information**: Credit cards, CVV codes, expiration dates, cardholder names
- **Cryptocurrency Keys**: Bitcoin, Ethereum, Monero, Litecoin, Dogecoin addresses and private keys
- **API Keys & Tokens**: GitHub, AWS, Stripe, Google, Firebase, JWT tokens
- **Cryptographic Keys**: SSH keys, SSL certificates, PGP keys
- **Wallet Security**: Seed phrases and mnemonic recovery phrases
- **Login Credentials**: Username/password pairs with site associations

### 🛡️ **Security Features**
- **Advanced Validation**: Luhn algorithm for credit cards, checksum validation for crypto addresses
- **Smart Grouping**: Related credentials are automatically grouped together
- **Context Analysis**: Shows surrounding text for better understanding
- **Security Warnings**: Comprehensive alerts for detected sensitive data
- **Data Masking**: Sensitive information is masked in displays for security

### ⚙️ **Technical Features**
- **Batch Processing**: Scan multiple files or entire folders
- **Real-time Progress**: Progress bar and status updates during scanning
- **Enhanced Export**: Organized results with security recommendations
- **Configurable Options**: Choose what types of information to scan for
- **File Type Filtering**: Support for text, JSON, CSV, log files and more

## Installation

1. Install Python 3.7 or higher
2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   python payment_scanner.py
   ```

2. **Select Files**: Use "Select Files" for individual files or "Select Folder" for batch scanning

3. **Configure Scan Options**: Choose which types of information to detect:
   - 💳 **Payment Data**: Credit cards, CVV codes, expiration dates
   - 🔑 **Crypto Keys**: Bitcoin, Ethereum, and other cryptocurrency data
   - 🔐 **Credentials**: Login pairs, API keys, SSH keys
   - 📧 **Contact Info**: Email addresses, phone numbers, names

4. **Start Scan**: Click "Start Scan" to begin the process

5. **View Results**: Check the "Results" tab to see organized, categorized findings

6. **Export**: Save comprehensive results with security recommendations

## Supported Detection Types

### 💳 **Payment Information**
- **Credit Cards**: Visa, MasterCard, American Express, Discover, Diners Club, JCB
- **Security Codes**: CVV/CVC codes with context detection
- **Expiration Dates**: Various date formats (MM/YY, MM/YYYY)
- **Cardholder Names**: Names associated with payment data

### 🔑 **Cryptocurrency**
- **Bitcoin**: Legacy addresses (1xxx), Bech32 (bc1xxx), P2SH (3xxx), private keys
- **Ethereum**: Addresses (0x...), private keys, keystore files
- **Other Coins**: Monero, Litecoin, Dogecoin, Ripple, Cardano, Solana addresses

### 🔐 **Keys & Tokens**
- **API Keys**: GitHub, AWS, Stripe, PayPal, Google, Firebase, Discord, Slack
- **Cryptographic Keys**: SSH (RSA, DSA, ECDSA), SSL certificates, PGP keys
- **Authentication**: JWT tokens, OAuth tokens
- **Wallet Security**: BIP39 seed phrases (12/24 words)

### 👤 **Credentials**
- **Login Pairs**: Username/password combinations with site associations
- **Contact Data**: Email addresses, phone numbers
- **URLs & Domains**: Associated websites and services

## File Types Supported

By default scans: `.txt`, `.log`, `.csv`, `.json`, `.xml`, `.html`, `.doc`, `.docx`

You can customize file extensions in the Settings tab.

## Applications

### 🔒 **Security Auditing**
- Identify exposed sensitive data in codebases
- Compliance scanning for PCI DSS, GDPR requirements
- Pre-deployment security checks
- Data leak prevention

### 🏢 **Enterprise Use Cases**
- Employee workstation security audits
- Server log analysis for credential exposure
- Configuration file security reviews
- Incident response and forensics

### 💰 **Cryptocurrency Security**
- Wallet security audits
- Private key exposure detection
- Exchange API key management
- Seed phrase security verification

## 🚨 Critical Security Warnings

### ⚠️ **When Sensitive Data is Detected:**

1. **🔒 IMMEDIATE ACTIONS:**
   - Encrypt or secure files containing sensitive data
   - Restrict access to authorized personnel only
   - Change exposed passwords and API keys immediately
   - Move cryptocurrency funds to secure wallets

2. **🔄 ONGOING SECURITY:**
   - Implement proper secret management systems
   - Use environment variables for sensitive configuration
   - Enable two-factor authentication where possible
   - Regular security audits and monitoring

3. **📋 COMPLIANCE:**
   - Follow PCI DSS standards for payment data
   - Comply with data protection regulations (GDPR, CCPA)
   - Document security incidents and remediation
   - Train staff on secure data handling

## Legal and Ethical Use

⚖️ **This tool is designed for legitimate security auditing and compliance purposes only.**

- ✅ **Authorized Use**: Only scan files you own or have explicit permission to audit
- ✅ **Security Auditing**: Use for identifying and securing sensitive data exposure
- ✅ **Compliance**: Help meet regulatory requirements for data protection
- ❌ **Unauthorized Access**: Never use to scan files without proper authorization
- ❌ **Malicious Intent**: Not for data theft or unauthorized access

## License

This project is provided as-is for educational and security auditing purposes. Users are responsible for ensuring compliance with applicable laws and regulations.
