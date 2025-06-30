#!/usr/bin/env python3
"""
Payment Information Scanner
A GUI application to scan files and text for payment information like credit card numbers and names.
"""

import sys
import re
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, 
                            QWidget, QPushButton, QTextEdit, QLabel, QFileDialog,
                            QListWidget, QSplitter, QGroupBox, QCheckBox, QProgressBar,
                            QMessageBox, QTabWidget, QLineEdit, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from key_utils import CryptoKeyDetector, detect_all_crypto_keys

class ScannerThread(QThread):
    """Background thread for scanning operations"""
    progress_updated = pyqtSignal(int)
    result_found = pyqtSignal(str, str, str)  # file_path, info_type, content
    scan_completed = pyqtSignal()
    
    def __init__(self, files_to_scan, scan_options):
        super().__init__()
        self.files_to_scan = files_to_scan
        self.scan_options = scan_options
        self.crypto_detector = CryptoKeyDetector()
        
    def run(self):
        total_files = len(self.files_to_scan)
        
        for i, file_path in enumerate(self.files_to_scan):
            try:
                self.scan_file(file_path)
                progress = int((i + 1) / total_files * 100)
                self.progress_updated.emit(progress)
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
                
        self.scan_completed.emit()
    
    def scan_file(self, file_path):
        """Scan a single file for payment information"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
                
            # Scan for credit card numbers
            if self.scan_options.get('credit_cards', True):
                self.scan_credit_cards(file_path, content)
                
            # Scan for names
            if self.scan_options.get('names', True):
                self.scan_names(file_path, content)
                
            # Scan for email addresses
            if self.scan_options.get('emails', True):
                self.scan_emails(file_path, content)
                
            # Scan for phone numbers
            if self.scan_options.get('phones', True):
                self.scan_phone_numbers(file_path, content)
                
            # Scan for crypto keys and credentials
            if self.scan_options.get('crypto_keys', True):
                self.scan_crypto_keys(file_path, content)
                
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
    def scan_credit_cards(self, file_path, content):
        """Scan for credit card numbers"""
        # Common credit card patterns
        patterns = [
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b5[1-5][0-9]{14}\b',          # MasterCard
            r'\b3[47][0-9]{13}\b',           # American Express
            r'\b6(?:011|5[0-9]{2})[0-9]{12}\b',  # Discover
            r'\b[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b'  # Generic format
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                card_number = match.group().strip()
                if self.luhn_check(re.sub(r'[-\s]', '', card_number)):
                    self.result_found.emit(file_path, "Credit Card", card_number)
    
    def scan_names(self, file_path, content):
        """Scan for potential names"""
        # Pattern for names (capitalized words)
        name_pattern = r'\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b'
        matches = re.finditer(name_pattern, content)
        
        for match in matches:
            name = match.group().strip()
            # Filter out common false positives
            if not self.is_common_false_positive(name):
                self.result_found.emit(file_path, "Name", name)
    
    def scan_emails(self, file_path, content):
        """Scan for email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        matches = re.finditer(email_pattern, content)
        
        for match in matches:
            email = match.group().strip()
            self.result_found.emit(file_path, "Email", email)
    
    def scan_phone_numbers(self, file_path, content):
        """Scan for phone numbers"""
        phone_patterns = [
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',  # US format
            r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',    # (123) 456-7890
            r'\+\d{1,3}[-.\s]?\d{1,14}',       # International
        ]
        
        for pattern in phone_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                phone = match.group().strip()
                self.result_found.emit(file_path, "Phone", phone)
    
    def luhn_check(self, card_number):
        """Validate credit card number using Luhn algorithm"""
        def digits_of(n):
            return [int(d) for d in str(n)]
        
        digits = digits_of(card_number)
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        checksum = sum(odd_digits)
        for d in even_digits:
            checksum += sum(digits_of(d*2))
        return checksum % 10 == 0
    
    def scan_crypto_keys(self, file_path, content):
        """Scan for cryptocurrency keys and credentials"""
        try:
            crypto_results = detect_all_crypto_keys(content, file_path)
            
            # Process raw results
            for result in crypto_results['raw_results']:
                result_type = f"{result['type']} - {result['subtype']}"
                self.result_found.emit(file_path, result_type, result['value'])
            
            # Process login pairs
            for pair in crypto_results['login_pairs']:
                login_info = f"Login: {pair['login']} | Password: {pair['password']} | Site: {pair['site']}"
                self.result_found.emit(file_path, "Login Pair", login_info)
                
        except Exception as e:
            print(f"Error scanning crypto keys in {file_path}: {e}")
    
    def is_common_false_positive(self, name):
        """Filter out common false positives for names"""
        false_positives = {
            'New York', 'Los Angeles', 'San Francisco', 'United States',
            'Credit Card', 'Social Security', 'Date Time', 'File Name',
            'User Name', 'First Name', 'Last Name', 'Full Name'
        }
        return name in false_positives

class PaymentScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_results = []
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Payment Information Scanner")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Scanner tab
        scanner_tab = QWidget()
        tab_widget.addTab(scanner_tab, "Scanner")
        self.setup_scanner_tab(scanner_tab)
        
        # Results tab
        results_tab = QWidget()
        tab_widget.addTab(results_tab, "Results")
        self.setup_results_tab(results_tab)
        
        # Settings tab
        settings_tab = QWidget()
        tab_widget.addTab(settings_tab, "Settings")
        self.setup_settings_tab(settings_tab)
        
        # Status bar
        self.statusBar().showMessage("Ready to scan")
        
    def setup_scanner_tab(self, tab):
        """Setup the main scanner interface"""
        layout = QVBoxLayout(tab)
        
        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_group)
        
        # Buttons for file operations
        button_layout = QHBoxLayout()
        self.select_files_btn = QPushButton("Select Files")
        self.select_folder_btn = QPushButton("Select Folder")
        self.clear_files_btn = QPushButton("Clear List")
        
        self.select_files_btn.clicked.connect(self.select_files)
        self.select_folder_btn.clicked.connect(self.select_folder)
        self.clear_files_btn.clicked.connect(self.clear_file_list)
        
        button_layout.addWidget(self.select_files_btn)
        button_layout.addWidget(self.select_folder_btn)
        button_layout.addWidget(self.clear_files_btn)
        button_layout.addStretch()
        
        file_layout.addLayout(button_layout)
        
        # File list
        self.file_list = QListWidget()
        file_layout.addWidget(self.file_list)
        
        layout.addWidget(file_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QHBoxLayout(options_group)
        
        self.scan_credit_cards = QCheckBox("Credit Cards")
        self.scan_names = QCheckBox("Names")
        self.scan_emails = QCheckBox("Email Addresses")
        self.scan_phones = QCheckBox("Phone Numbers")
        self.scan_crypto_keys = QCheckBox("Crypto Keys & Credentials")
        
        # Set default selections
        self.scan_credit_cards.setChecked(True)
        self.scan_names.setChecked(True)
        self.scan_emails.setChecked(True)
        self.scan_phones.setChecked(True)
        self.scan_crypto_keys.setChecked(True)
        
        options_layout.addWidget(self.scan_credit_cards)
        options_layout.addWidget(self.scan_names)
        options_layout.addWidget(self.scan_emails)
        options_layout.addWidget(self.scan_phones)
        options_layout.addWidget(self.scan_crypto_keys)
        options_layout.addStretch()
        
        layout.addWidget(options_group)
        
        # Progress and scan controls
        control_layout = QHBoxLayout()
        
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }")
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        control_layout.addWidget(self.scan_btn)
        control_layout.addWidget(self.progress_bar)
        control_layout.addStretch()
        
        layout.addLayout(control_layout)
        
    def setup_results_tab(self, tab):
        """Setup the results display tab"""
        layout = QVBoxLayout(tab)
        
        # Results summary
        summary_layout = QHBoxLayout()
        self.results_label = QLabel("No scan results yet")
        self.results_label.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setEnabled(False)
        
        summary_layout.addWidget(self.results_label)
        summary_layout.addStretch()
        summary_layout.addWidget(self.export_btn)
        
        layout.addLayout(summary_layout)
        
        # Results display
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Courier", 10))
        layout.addWidget(self.results_text)
        
    def setup_settings_tab(self, tab):
        """Setup the settings tab"""
        layout = QVBoxLayout(tab)
        
        # File type filters
        filter_group = QGroupBox("File Type Filters")
        filter_layout = QVBoxLayout(filter_group)
        
        self.file_extensions = QLineEdit()
        self.file_extensions.setText(".txt,.log,.csv,.json,.xml,.html")
        self.file_extensions.setPlaceholderText("Enter file extensions separated by commas")
        
        filter_layout.addWidget(QLabel("File Extensions to Scan:"))
        filter_layout.addWidget(self.file_extensions)
        
        layout.addWidget(filter_group)
        
        # Scan sensitivity
        sensitivity_group = QGroupBox("Scan Sensitivity")
        sensitivity_layout = QVBoxLayout(sensitivity_group)
        
        self.sensitivity_combo = QComboBox()
        self.sensitivity_combo.addItems(["Low", "Medium", "High"])
        self.sensitivity_combo.setCurrentText("Medium")
        
        sensitivity_layout.addWidget(QLabel("Detection Sensitivity:"))
        sensitivity_layout.addWidget(self.sensitivity_combo)
        
        layout.addWidget(sensitivity_group)
        
        layout.addStretch()
        
    def select_files(self):
        """Select individual files to scan"""
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Files to Scan", "", 
            "All Files (*);;Text Files (*.txt);;Log Files (*.log);;CSV Files (*.csv)"
        )
        
        for file_path in files:
            if file_path not in [self.file_list.item(i).text() for i in range(self.file_list.count())]:
                self.file_list.addItem(file_path)
                
        self.update_scan_button_state()
        
    def select_folder(self):
        """Select a folder and add all files from it"""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        
        if folder:
            extensions = [ext.strip() for ext in self.file_extensions.text().split(',')]
            
            for root, dirs, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_ext = os.path.splitext(file)[1].lower()
                    
                    if not extensions or any(file_ext == ext for ext in extensions):
                        if file_path not in [self.file_list.item(i).text() for i in range(self.file_list.count())]:
                            self.file_list.addItem(file_path)
                            
        self.update_scan_button_state()
        
    def clear_file_list(self):
        """Clear the file list"""
        self.file_list.clear()
        self.update_scan_button_state()
        
    def update_scan_button_state(self):
        """Enable/disable scan button based on file list"""
        self.scan_btn.setEnabled(self.file_list.count() > 0)
        
    def start_scan(self):
        """Start the scanning process"""
        if self.file_list.count() == 0:
            QMessageBox.warning(self, "Warning", "Please select files to scan first.")
            return
            
        # Get files to scan
        files_to_scan = [self.file_list.item(i).text() for i in range(self.file_list.count())]
        
        # Get scan options
        scan_options = {
            'credit_cards': self.scan_credit_cards.isChecked(),
            'names': self.scan_names.isChecked(),
            'emails': self.scan_emails.isChecked(),
            'phones': self.scan_phones.isChecked(),
            'crypto_keys': self.scan_crypto_keys.isChecked()
        }
        
        # Clear previous results
        self.scan_results.clear()
        self.results_text.clear()
        
        # Setup UI for scanning
        self.scan_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.statusBar().showMessage("Scanning in progress...")
        
        # Start scanner thread
        self.scanner_thread = ScannerThread(files_to_scan, scan_options)
        self.scanner_thread.progress_updated.connect(self.update_progress)
        self.scanner_thread.result_found.connect(self.add_result)
        self.scanner_thread.scan_completed.connect(self.scan_finished)
        self.scanner_thread.start()
        
    def update_progress(self, value):
        """Update progress bar"""
        self.progress_bar.setValue(value)
        
    def add_result(self, file_path, info_type, content):
        """Add a scan result"""
        result = {
            'file': file_path,
            'type': info_type,
            'content': content
        }
        self.scan_results.append(result)
        
        # Update results display with better formatting
        if 'Login Pair' in info_type:
            result_text = f"🔐 [{info_type}] {content} (in {os.path.basename(file_path)})\n"
        elif any(crypto_type in info_type for crypto_type in ['Bitcoin', 'Ethereum', 'Cryptocurrency', 'API Key', 'Seed Phrase']):
            result_text = f"🔑 [{info_type}] {content} (in {os.path.basename(file_path)})\n"
        elif 'Cryptographic Key' in info_type:
            result_text = f"🛡️ [{info_type}] {content} (in {os.path.basename(file_path)})\n"
        elif 'Credit Card' in info_type:
            result_text = f"💳 [{info_type}] {content} (in {os.path.basename(file_path)})\n"
        else:
            result_text = f"📄 [{info_type}] {content} (in {os.path.basename(file_path)})\n"
        
        self.results_text.append(result_text)
        
    def scan_finished(self):
        """Handle scan completion"""
        self.scan_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Update results summary
        total_results = len(self.scan_results)
        if total_results > 0:
            self.results_label.setText(f"Found {total_results} potential payment information items")
            self.export_btn.setEnabled(True)
            self.statusBar().showMessage(f"Scan completed. Found {total_results} items.")
        else:
            self.results_label.setText("No payment information found")
            self.export_btn.setEnabled(False)
            self.statusBar().showMessage("Scan completed. No items found.")
            
        # Show completion message
        QMessageBox.information(self, "Scan Complete", 
                              f"Scan completed successfully!\nFound {total_results} potential payment information items.")
        
    def export_results(self):
        """Export scan results to a file"""
        if not self.scan_results:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "scan_results.txt", 
            "Text Files (*.txt);;CSV Files (*.csv)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Enhanced Payment & Crypto Information Scanner Results\n")
                    f.write("=" * 60 + "\n\n")
                    
                    # Group results by type for better organization
                    grouped_results = {}
                    for result in self.scan_results:
                        result_type = result['type']
                        if result_type not in grouped_results:
                            grouped_results[result_type] = []
                        grouped_results[result_type].append(result)
                    
                    # Write summary
                    f.write(f"SCAN SUMMARY\n")
                    f.write(f"Total items found: {len(self.scan_results)}\n")
                    for result_type, items in grouped_results.items():
                        f.write(f"  {result_type}: {len(items)} items\n")
                    f.write("\n" + "=" * 60 + "\n\n")
                    
                    # Write detailed results grouped by type
                    for result_type, items in grouped_results.items():
                        f.write(f"{result_type.upper()} ({len(items)} found)\n")
                        f.write("-" * 40 + "\n")
                        
                        for i, result in enumerate(items, 1):
                            f.write(f"{i}. Content: {result['content']}\n")
                            f.write(f"   File: {result['file']}\n")
                            f.write(f"   Type: {result['type']}\n")
                            f.write("\n")
                        
                        f.write("\n")
                    
                    # Add security warnings
                    f.write("SECURITY WARNINGS\n")
                    f.write("=" * 60 + "\n")
                    f.write("⚠️  Sensitive information detected! Please ensure:\n")
                    f.write("• Files containing this data are properly encrypted\n")
                    f.write("• Access is restricted to authorized personnel only\n")
                    f.write("• Data is handled according to security policies\n")
                    f.write("• Consider removing or securing detected credentials\n")
                    f.write("• Crypto keys should be stored in secure wallets\n")
                        
                QMessageBox.information(self, "Export Complete", f"Results exported to {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Payment Scanner")
    app.setApplicationVersion("1.0")
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = PaymentScannerApp()
    window.show()
    
    # Start event loop
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
