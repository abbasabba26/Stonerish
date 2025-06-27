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
from key_utils import decrypt_license

class PaymentScanner:
    """Enhanced payment information scanner with multiple detection patterns"""
    
    def __init__(self):
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
            # Trial mode - show enhanced sample results
            sample_results = [
                {'type': 'Credit Card', 'subtype': 'Visa', 'value': '4111****1111', 'file': 'sample.txt'},
                {'type': 'Credit Card', 'subtype': 'MasterCard', 'value': '5555****4444', 'file': 'sample.txt'},
                {'type': 'Expiration Date', 'subtype': 'Date', 'value': '12/25', 'file': 'sample.txt'},
                {'type': 'Security Code', 'subtype': 'CVV/CVC', 'value': '123', 'file': 'sample.txt'},
                {'type': 'Cardholder Name', 'subtype': 'Name', 'value': 'John Doe', 'file': 'sample.txt'},
                {'type': 'Cardholder Name', 'subtype': 'Name', 'value': 'Jane Smith', 'file': 'sample.txt'}
            ]
            self.display_results(sample_results)
            QMessageBox.information(self, "Trial Mode", 
                "This is a trial preview showing sample payment data detection.\n\n"
                "Full version can scan for:\n"
                "• Credit card numbers (Visa, MasterCard, Amex, etc.)\n"
                "• Cardholder names\n"
                "• CVV/CVC security codes\n"
                "• Expiration dates\n"
                "• Multiple file formats\n\n"
                "Purchase a license for full functionality.")
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
            self.result_box.setText("No payment information found.")
            return

        # Group results by type
        grouped = {}
        for result in results:
            result_type = result['type']
            if result_type not in grouped:
                grouped[result_type] = []
            grouped[result_type].append(result)

        # Format output
        output = []
        output.append(f"PAYMENT INFORMATION SCAN RESULTS")
        output.append(f"Found {len(results)} potential payment data items")
        output.append("=" * 60)
        
        for result_type, items in grouped.items():
            output.append(f"\n{result_type.upper()} ({len(items)} found):")
            output.append("-" * 40)
            
            for i, item in enumerate(items, 1):
                output.append(f"  {i}. {item['subtype']}: {item['value']}")
                output.append(f"     File: {os.path.basename(item['file'])}")
                if len(items) > 3 and i == 3:  # Limit display in trial mode
                    if not self.license_info:
                        output.append(f"     ... and {len(items) - 3} more (license required)")
                        break
                output.append("")

        # Add security warning
        output.append("\n" + "!" * 60)
        output.append("SECURITY WARNING:")
        output.append("Payment information detected! Ensure these files are:")
        output.append("• Properly encrypted")
        output.append("• Access-controlled")
        output.append("• Compliant with PCI DSS standards")
        output.append("!" * 60)

        self.result_box.setText("\n".join(output))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ScannerApp()
    window.show()
    sys.exit(app.exec())

