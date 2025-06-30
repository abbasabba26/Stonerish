import sys
import os
import json
import re
from datetime import datetime
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QFileDialog, QTextEdit, QMessageBox,
    QCheckBox, QGroupBox, QHBoxLayout, QProgressBar
)
from PyQt6.QtCore import QThread, pyqtSignal
from key_utils import decrypt_license, CryptoKeyDetector, detect_all_crypto_keys

class PaymentScanner:
    """Enhanced payment information scanner with multiple detection patterns"""
    
    def __init__(self):
        # Initialize crypto detector
        self.crypto_detector = CryptoKeyDetector()
        
        # Credit card patterns (major card types)
        self.card_patterns = {
            'Visa': r'\b4[0-9]{12}(?:[0-9]{3})?\b',
            'MasterCard': r'\b5[1-5][0-9]{14}\b',
            'American Express': r'\b3[47][0-9]{13}\b',
            'Discover': r'\b6(?:011|5[0-9]{2})[0-9]{12}\b',
            'Diners Club': r'\b3[0689][0-9]{11}\b',
            'JCB': r'\b(?:2131|1800|35\d{3})\d{11}\b',
            'Generic Card': r'\b[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
        }
        
        # CVV patterns with context
        self.cvv_patterns = [
            r'(?i)\b(?:cvv|cvc|security\s+code|card\s+code)[\s:]*([0-9]{3,4})\b',
            r'(?i)\b(?:cvv|cvc)[\s]*:?[\s]*([0-9]{3,4})\b'
        ]
        
        # Expiration date patterns
        self.expiry_patterns = [
            r'\b(0[1-9]|1[0-2])\/([0-9]{2}|20[0-9]{2})\b',  # MM/YY or MM/YYYY
            r'\b(0[1-9]|1[0-2])\-([0-9]{2}|20[0-9]{2})\b',  # MM-YY or MM-YYYY
            r'(?i)\b(?:exp|expiry|expires?)[\s:]*([0-9]{1,2}[\/\-][0-9]{2,4})\b'
        ]
        
        # Name patterns (cardholder names)
        self.name_patterns = [
            r'(?i)\b(?:name|cardholder|holder)[\s:]+([A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b',
            r'(?i)\b(?:card\s+name|name\s+on\s+card)[\s:]+([A-Z][a-z]+\s+[A-Z][a-z]+)\b',
            r'\b([A-Z][A-Z\s]{2,30})\b(?=.*(?:visa|mastercard|amex|discover|card))'  # All caps names near card info
        ]

    def luhn_check(self, card_number):
        """Validate credit card number using Luhn algorithm"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number.replace(' ', '').replace('-', ''))
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        return checksum % 10 == 0

    def scan_content(self, content, filename):
        """Scan content for payment information"""
        results = []
        
        # Scan for credit cards
        for card_type, pattern in self.card_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                card_num = match.group().replace(' ', '').replace('-', '')
                if len(card_num) >= 13 and self.luhn_check(card_num):
                    # Mask the card number for security
                    masked = card_num[:4] + '*' * (len(card_num) - 8) + card_num[-4:]
                    results.append({
                        'type': 'Credit Card',
                        'subtype': card_type,
                        'value': masked,
                        'original': match.group(),
                        'file': filename
                    })
        
        # Scan for CVV codes
        for pattern in self.cvv_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                cvv = match.group(1) if match.groups() else match.group()
                results.append({
                    'type': 'Security Code',
                    'subtype': 'CVV/CVC',
                    'value': cvv,
                    'original': match.group(),
                    'file': filename
                })
        
        # Scan for expiration dates
        for pattern in self.expiry_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                date_val = match.group(1) if match.groups() else match.group()
                results.append({
                    'type': 'Expiration Date',
                    'subtype': 'Date',
                    'value': date_val,
                    'original': match.group(),
                    'file': filename
                })
        
        # Scan for cardholder names
        for pattern in self.name_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                name = match.group(1) if match.groups() else match.group()
                name = name.strip()
                if len(name.split()) >= 2 and len(name) > 5:  # At least first and last name
                    results.append({
                        'type': 'Cardholder Name',
                        'subtype': 'Name',
                        'value': name,
                        'original': match.group(),
                        'file': filename
                    })
        
        # Add crypto key detection
        crypto_results = detect_all_crypto_keys(content, filename)
        
        # Process crypto detection results
        for result in crypto_results['raw_results']:
            results.append({
                'type': f"{result['type']} - {result['subtype']}",
                'subtype': result['subtype'],
                'value': result['value'],
                'original': result.get('full_value', result['value']),
                'file': filename,
                'context': result.get('context', '')
            })
        
        # Process login pairs
        for pair in crypto_results['login_pairs']:
            results.append({
                'type': 'Login Credentials',
                'subtype': 'Username/Password Pair',
                'value': f"User: {pair['login']} | Pass: {pair['password']} | Site: {pair['site']}",
                'original': f"Login: {pair['login']}, Password: {pair['password']}, Site: {pair['site']}",
                'file': filename,
                'context': f"Associated with {pair['site']}"
            })
        
        return results

class ScanWorker(QThread):
    """Worker thread for scanning files"""
    progress = pyqtSignal(int)
    result = pyqtSignal(list)
    status = pyqtSignal(str)
    
    def __init__(self, folder_path, file_types, scanner):
        super().__init__()
        self.folder_path = folder_path
        self.file_types = file_types
        self.scanner = scanner
        
    def run(self):
        results = []
        files_to_scan = []
        
        # Collect all files to scan
        for root, _, files in os.walk(self.folder_path):
            for file in files:
                if any(file.lower().endswith(ext) for ext in self.file_types):
                    files_to_scan.append(os.path.join(root, file))
        
        total_files = len(files_to_scan)
        if total_files == 0:
            self.status.emit("No files found to scan")
            self.result.emit([])
            return
        
        for i, file_path in enumerate(files_to_scan):
            try:
                self.status.emit(f"Scanning: {os.path.basename(file_path)}")
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    file_results = self.scanner.scan_content(content, file_path)
                    results.extend(file_results)
                
                progress = int((i + 1) / total_files * 100)
                self.progress.emit(progress)
                
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
                continue
        
        self.status.emit(f"Scan complete. Found {len(results)} potential matches.")
        self.result.emit(results)

class ScannerApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Payment Information Scanner")
        self.setGeometry(200, 200, 600, 500)
        self.license_info = None
        self.scanner = PaymentScanner()
        self.scan_worker = None
        self.last_results = []

        layout = QVBoxLayout()

        # Status section
        self.status_label = QLabel("Trial Mode: Limited Preview Only")
        self.status_label.setStyleSheet("color: red; font-weight: bold;")
        layout.addWidget(self.status_label)

        # License section
        self.load_license_btn = QPushButton("Load License File")
        self.load_license_btn.clicked.connect(self.load_license)
        layout.addWidget(self.load_license_btn)

        # File type selection
        file_group = QGroupBox("File Types to Scan")
        file_layout = QVBoxLayout()
        
        self.file_types = {
            '.txt': QCheckBox("Text Files (.txt)"),
            '.doc': QCheckBox("Word Documents (.doc)"),
            '.docx': QCheckBox("Word Documents (.docx)"),
            '.csv': QCheckBox("CSV Files (.csv)"),
            '.log': QCheckBox("Log Files (.log)"),
            '.json': QCheckBox("JSON Files (.json)")
        }
        
        # Default selections
        self.file_types['.txt'].setChecked(True)
        self.file_types['.csv'].setChecked(True)
        
        for checkbox in self.file_types.values():
            file_layout.addWidget(checkbox)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # Scan controls
        scan_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.run_scan)
        scan_layout.addWidget(self.scan_btn)
        
        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        scan_layout.addWidget(self.stop_btn)
        
        layout.addLayout(scan_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Status label for current file
        self.current_file_label = QLabel("")
        layout.addWidget(self.current_file_label)

        # Results section
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        layout.addWidget(self.result_box)

        self.setLayout(layout)

    def load_license(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select License File", "", "License Files (*.lic)")
        if path:
            try:
                with open(path, "r") as f:
                    decrypted = decrypt_license(f.read())
                    data = json.loads(decrypted)
                    expiry = datetime.strptime(data["expiry"], "%Y-%m-%d")
                    if expiry < datetime.now():
                        raise ValueError("License expired.")
                    self.license_info = data
                    self.status_label.setText(f"Licensed to: {data['user']} (Expires: {data['expiry']})")
                    self.status_label.setStyleSheet("color: green; font-weight: bold;")
            except Exception as e:
                QMessageBox.critical(self, "License Error", f"Invalid license: {e}")

    def run_scan(self):
        if not self.license_info:
            # Trial mode - show enhanced sample results with crypto data
            sample_results = [
                {'type': 'Credit Card', 'subtype': 'Visa', 'value': '4111****1111', 'file': 'sample.txt', 'context': 'Payment form data'},
                {'type': 'Credit Card', 'subtype': 'MasterCard', 'value': '5555****4444', 'file': 'sample.txt', 'context': 'Stored payment info'},
                {'type': 'Expiration Date', 'subtype': 'Date', 'value': '12/25', 'file': 'sample.txt', 'context': 'Card expiry'},
                {'type': 'Security Code', 'subtype': 'CVV/CVC', 'value': '123', 'file': 'sample.txt', 'context': 'Security code'},
                {'type': 'Cardholder Name', 'subtype': 'Name', 'value': 'John Doe', 'file': 'sample.txt', 'context': 'Cardholder info'},
                {'type': 'Bitcoin - Bitcoin Address (Legacy)', 'subtype': 'Bitcoin Address', 'value': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'file': 'crypto.txt', 'context': 'Bitcoin wallet address'},
                {'type': 'Ethereum - Ethereum Address', 'subtype': 'Ethereum Address', 'value': '0x742d35Cc6634C0532925a3b8D4C0d886E', 'file': 'crypto.txt', 'context': 'Ethereum wallet'},
                {'type': 'API Key - GitHub Token', 'subtype': 'GitHub Token', 'value': 'ghp_****************************', 'file': 'config.txt', 'context': 'GitHub API access'},
                {'type': 'Login Credentials', 'subtype': 'Username/Password Pair', 'value': 'User: admin@example.com | Pass: ******** | Site: example.com', 'file': 'credentials.txt', 'context': 'Login credentials'},
                {'type': 'Seed Phrase - 12-word Seed Phrase', 'subtype': '12-word Seed Phrase', 'value': 'abandon ability able ... zebra zone', 'file': 'wallet.txt', 'context': 'Wallet recovery phrase'}
            ]
            self.display_results(sample_results)
            QMessageBox.information(self, "Trial Mode", 
                "This is a trial preview showing sample sensitive data detection.\n\n"
                "Full version can scan for:\n"
                "💳 PAYMENT DATA:\n"
                "• Credit card numbers (Visa, MasterCard, Amex, etc.)\n"
                "• Cardholder names, CVV codes, expiration dates\n\n"
                "🔑 CRYPTOCURRENCY:\n"
                "• Bitcoin, Ethereum, and other crypto addresses\n"
                "• Private keys and wallet seed phrases\n\n"
                "🔐 CREDENTIALS & KEYS:\n"
                "• API keys (GitHub, AWS, Stripe, etc.)\n"
                "• SSH keys, SSL certificates\n"
                "• Username/password pairs with site associations\n\n"
                "📁 MULTIPLE FILE FORMATS:\n"
                "• Text, JSON, CSV, Log files and more\n\n"
                "Purchase a license for full functionality and unlimited scanning.")
            return

        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if not folder:
            return

        # Get selected file types
        selected_types = [ext for ext, checkbox in self.file_types.items() if checkbox.isChecked()]
        if not selected_types:
            QMessageBox.warning(self, "No File Types", "Please select at least one file type to scan.")
            return

        # Start scanning
        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.result_box.clear()
        
        self.scan_worker = ScanWorker(folder, selected_types, self.scanner)
        self.scan_worker.progress.connect(self.progress_bar.setValue)
        self.scan_worker.result.connect(self.display_results)
        self.scan_worker.status.connect(self.current_file_label.setText)
        self.scan_worker.finished.connect(self.scan_finished)
        self.scan_worker.start()

    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.terminate()
            self.scan_finished()

    def scan_finished(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.current_file_label.setText("")

    def display_results(self, results):
        self.last_results = results
        if not results:
            self.result_box.setText("No sensitive information found.")
            return

        # Group results by main category
        grouped = {}
        for result in results:
            result_type = result['type']
            # Create main categories
            if any(crypto in result_type for crypto in ['Bitcoin', 'Ethereum', 'Cryptocurrency']):
                main_type = '🔑 CRYPTOCURRENCY KEYS'
            elif 'API Key' in result_type:
                main_type = '🔐 API KEYS & TOKENS'
            elif 'Cryptographic Key' in result_type:
                main_type = '🛡️ CRYPTOGRAPHIC KEYS'
            elif 'Seed Phrase' in result_type:
                main_type = '🌱 WALLET SEED PHRASES'
            elif 'Login Credentials' in result_type:
                main_type = '👤 LOGIN CREDENTIALS'
            elif 'Credit Card' in result_type:
                main_type = '💳 PAYMENT CARDS'
            elif result_type in ['Expiration Date', 'Security Code']:
                main_type = '💳 PAYMENT CARDS'
            elif result_type == 'Cardholder Name':
                main_type = '💳 PAYMENT CARDS'
            else:
                main_type = '📄 OTHER SENSITIVE DATA'
            
            if main_type not in grouped:
                grouped[main_type] = []
            grouped[main_type].append(result)

        # Format output with enhanced grouping
        output = []
        output.append("🔍 ENHANCED SECURITY SCAN RESULTS")
        output.append(f"Found {len(results)} sensitive data items across {len(grouped)} categories")
        output.append("=" * 70)
        
        # Summary by category
        output.append("\n📊 SUMMARY BY CATEGORY:")
        for main_type, items in grouped.items():
            output.append(f"  {main_type}: {len(items)} items")
        output.append("\n" + "=" * 70)
        
        # Detailed results by category
        for main_type, items in grouped.items():
            output.append(f"\n{main_type} ({len(items)} found)")
            output.append("─" * 50)
            
            # Group items by subtype within category
            subtype_groups = {}
            for item in items:
                subtype = item.get('subtype', item['type'])
                if subtype not in subtype_groups:
                    subtype_groups[subtype] = []
                subtype_groups[subtype].append(item)
            
            for subtype, subitems in subtype_groups.items():
                if len(subtype_groups) > 1:
                    output.append(f"\n  📋 {subtype} ({len(subitems)} found):")
                
                for i, item in enumerate(subitems, 1):
                    if len(subtype_groups) > 1:
                        prefix = "    "
                    else:
                        prefix = "  "
                    
                    output.append(f"{prefix}{i}. {item['value']}")
                    output.append(f"{prefix}   📁 File: {os.path.basename(item['file'])}")
                    
                    # Add context if available
                    if item.get('context'):
                        context = item['context'][:100] + '...' if len(item['context']) > 100 else item['context']
                        output.append(f"{prefix}   💬 Context: {context}")
                    
                    # Limit display in trial mode
                    if len(subitems) > 3 and i == 3 and not self.license_info:
                        output.append(f"{prefix}   ... and {len(subitems) - 3} more (license required)")
                        break
                    
                    output.append("")

        # Enhanced security warnings
        output.append("\n" + "⚠️ " * 20)
        output.append("🚨 CRITICAL SECURITY WARNINGS 🚨")
        output.append("⚠️ " * 20)
        output.append("\n🔴 SENSITIVE DATA DETECTED! Take immediate action:")
        output.append("• 🔒 Encrypt files containing this data immediately")
        output.append("• 🚫 Restrict access to authorized personnel only")
        output.append("• 📋 Review and update security policies")
        output.append("• 🗑️  Consider removing or securing detected credentials")
        output.append("• 💰 Move crypto keys to secure hardware wallets")
        output.append("• 🔄 Rotate compromised API keys and passwords")
        output.append("• 📊 Conduct security audit of affected systems")
        output.append("• 🏢 Ensure compliance with data protection regulations")
        
        if any('Login Credentials' in result['type'] for result in results):
            output.append("\n🔐 LOGIN CREDENTIAL SECURITY:")
            output.append("• Change passwords immediately if compromised")
            output.append("• Enable two-factor authentication where possible")
            output.append("• Use password managers for secure storage")
        
        if any(crypto in str(result) for result in results for crypto in ['Bitcoin', 'Ethereum', 'API Key']):
            output.append("\n💰 CRYPTOCURRENCY & API SECURITY:")
            output.append("• Transfer funds to secure wallets immediately")
            output.append("• Revoke and regenerate exposed API keys")
            output.append("• Monitor accounts for unauthorized access")
        
        output.append("\n" + "⚠️ " * 20)

        self.result_box.setText("\n".join(output))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerApp()
    window.show()
    sys.exit(app.exec())
