#!/usr/bin/env python3
"""
Enhanced Payment and Credential Scanner
Comprehensive tool for scanning files and network traffic for sensitive information
"""

import sys
import os
import re
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, 
    QPushButton, QTextEdit, QLabel, QFileDialog, QListWidget, 
    QSplitter, QGroupBox, QCheckBox, QProgressBar, QMessageBox, 
    QTabWidget, QLineEdit, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QSpinBox, QTextBrowser, QFrame
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QIcon, QPixmap

# Import our custom modules
try:
    from network_analyzer import NetworkAnalyzer, CredentialResult
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_AVAILABLE = False
    print("Network analysis not available - install scapy for full functionality")

try:
    from repository_scanner import RepositoryScanner, RepositoryResult
    REPO_SCANNER_AVAILABLE = True
except ImportError:
    REPO_SCANNER_AVAILABLE = False
    print("Repository scanner not available")

class NetworkScanThread(QThread):
    """Background thread for network scanning operations"""
    progress_updated = pyqtSignal(int)
    result_found = pyqtSignal(str, str, str, str)  # source, protocol, type, content
    scan_completed = pyqtSignal()
    status_updated = pyqtSignal(str)
    
    def __init__(self, scan_type, target, protocols, options=None):
        super().__init__()
        self.scan_type = scan_type  # 'pcap' or 'live'
        self.target = target  # file path or interface name
        self.protocols = protocols
        self.options = options or {}
        self.analyzer = NetworkAnalyzer() if NETWORK_AVAILABLE else None
        
    def run(self):
        if not self.analyzer:
            self.status_updated.emit("Network analysis not available")
            self.scan_completed.emit()
            return
            
        try:
            if self.scan_type == 'pcap':
                self.status_updated.emit(f"Analyzing PCAP file: {self.target}")
                results = self.analyzer.analyze_pcap_file(self.target, self.protocols)
                
                for i, result in enumerate(results):
                    self.result_found.emit(
                        result.source,
                        result.protocol,
                        result.credential_type,
                        f"{result.username}:{result.password}" if result.username and result.password 
                        else result.username or result.password or result.hash_value or str(result.additional_info)
                    )
                    progress = int((i + 1) / len(results) * 100)
                    self.progress_updated.emit(progress)
                    
            elif self.scan_type == 'live':
                packet_count = self.options.get('packet_count', 100)
                self.status_updated.emit(f"Starting live capture on {self.target} ({packet_count} packets)")
                
                # For live capture, we'll simulate progress
                self.analyzer.start_live_capture(self.target, self.protocols, packet_count)
                
                # Get results after capture
                results = self.analyzer.get_results()
                for result in results:
                    self.result_found.emit(
                        result.source,
                        result.protocol,
                        result.credential_type,
                        f"{result.username}:{result.password}" if result.username and result.password 
                        else result.username or result.password or result.hash_value or str(result.additional_info)
                    )
                    
        except Exception as e:
            self.status_updated.emit(f"Error: {str(e)}")
            
        self.scan_completed.emit()

class RepositoryScanThread(QThread):
    """Background thread for repository scanning operations"""
    progress_updated = pyqtSignal(int)
    result_found = pyqtSignal(str, str, str, str, str)  # file_path, repo_type, cred_type, content, confidence
    scan_completed = pyqtSignal()
    status_updated = pyqtSignal(str)
    
    def __init__(self, scan_path, scan_common=False):
        super().__init__()
        self.scan_path = scan_path
        self.scan_common = scan_common
        self.scanner = RepositoryScanner() if REPO_SCANNER_AVAILABLE else None
        
    def run(self):
        if not self.scanner:
            self.status_updated.emit("Repository scanner not available")
            self.scan_completed.emit()
            return
            
        try:
            if self.scan_common:
                self.status_updated.emit("Scanning common credential locations...")
                results = self.scanner.scan_common_locations()
            else:
                self.status_updated.emit(f"Scanning directory: {self.scan_path}")
                results = self.scanner.scan_directory(self.scan_path)
                
            for i, result in enumerate(results):
                self.result_found.emit(
                    result.file_path,
                    result.repository_type,
                    result.credential_type,
                    result.content,
                    result.confidence
                )
                progress = int((i + 1) / len(results) * 100)
                self.progress_updated.emit(progress)
                
        except Exception as e:
            self.status_updated.emit(f"Error: {str(e)}")
            
        self.scan_completed.emit()

class FileScanThread(QThread):
    """Background thread for file scanning operations (original functionality)"""
    progress_updated = pyqtSignal(int)
    result_found = pyqtSignal(str, str, str)  # file_path, info_type, content
    scan_completed = pyqtSignal()
    
    def __init__(self, files_to_scan, scan_options):
        super().__init__()
        self.files_to_scan = files_to_scan
        self.scan_options = scan_options
        
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
                
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
    def scan_credit_cards(self, file_path, content):
        """Scan for credit card numbers"""
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
        name_pattern = r'\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b'
        matches = re.finditer(name_pattern, content)
        
        for match in matches:
            name = match.group().strip()
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
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            r'\(\d{3}\)\s*\d{3}[-.]?\d{4}',
            r'\+\d{1,3}[-.\s]?\d{1,14}',
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
    
    def is_common_false_positive(self, name):
        """Filter out common false positives for names"""
        false_positives = {
            'New York', 'Los Angeles', 'San Francisco', 'United States',
            'Credit Card', 'Social Security', 'Date Time', 'File Name',
            'User Name', 'First Name', 'Last Name', 'Full Name'
        }
        return name in false_positives

class EnhancedScannerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.scan_results = []
        self.network_results = []
        self.repository_results = []
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Enhanced Payment & Credential Scanner v2.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tab widget for different scan types
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_file_scan_tab()
        self.create_network_scan_tab()
        self.create_repository_scan_tab()
        self.create_results_tab()
        self.create_settings_tab()
        
        # Status bar
        self.statusBar().showMessage("Ready")
        
    def create_file_scan_tab(self):
        """Create file scanning tab (original functionality)"""
        file_tab = QWidget()
        layout = QVBoxLayout(file_tab)
        
        # File selection section
        file_group = QGroupBox("File Selection")
        file_layout = QVBoxLayout(file_group)
        
        button_layout = QHBoxLayout()
        self.select_files_btn = QPushButton("Select Files")
        self.select_folder_btn = QPushButton("Select Folder")
        self.selected_files_list = QListWidget()
        self.selected_files_list.setMaximumHeight(100)
        
        button_layout.addWidget(self.select_files_btn)
        button_layout.addWidget(self.select_folder_btn)
        
        file_layout.addLayout(button_layout)
        file_layout.addWidget(QLabel("Selected Files:"))
        file_layout.addWidget(self.selected_files_list)
        
        # Scan options section
        options_group = QGroupBox("Scan Options")
        options_layout = QVBoxLayout(options_group)
        
        self.credit_cards_cb = QCheckBox("Credit Card Numbers")
        self.names_cb = QCheckBox("Names")
        self.emails_cb = QCheckBox("Email Addresses")
        self.phones_cb = QCheckBox("Phone Numbers")
        
        # Set default selections
        self.credit_cards_cb.setChecked(True)
        self.names_cb.setChecked(True)
        self.emails_cb.setChecked(True)
        self.phones_cb.setChecked(True)
        
        options_layout.addWidget(self.credit_cards_cb)
        options_layout.addWidget(self.names_cb)
        options_layout.addWidget(self.emails_cb)
        options_layout.addWidget(self.phones_cb)
        
        # Control buttons
        control_layout = QHBoxLayout()
        self.start_file_scan_btn = QPushButton("Start File Scan")
        self.export_file_results_btn = QPushButton("Export Results")
        
        control_layout.addWidget(self.start_file_scan_btn)
        control_layout.addWidget(self.export_file_results_btn)
        control_layout.addStretch()
        
        # Progress bar
        self.file_progress_bar = QProgressBar()
        
        # Add all sections to main layout
        layout.addWidget(file_group)
        layout.addWidget(options_group)
        layout.addLayout(control_layout)
        layout.addWidget(self.file_progress_bar)
        layout.addStretch()
        
        # Connect signals
        self.select_files_btn.clicked.connect(self.select_files)
        self.select_folder_btn.clicked.connect(self.select_folder)
        self.start_file_scan_btn.clicked.connect(self.start_file_scan)
        self.export_file_results_btn.clicked.connect(self.export_file_results)
        
        self.tab_widget.addTab(file_tab, "File Scanner")
        
    def create_network_scan_tab(self):
        """Create network scanning tab"""
        network_tab = QWidget()
        layout = QVBoxLayout(network_tab)
        
        if not NETWORK_AVAILABLE:
            warning_label = QLabel("⚠️ Network analysis requires 'scapy' package.\nInstall with: pip install scapy")
            warning_label.setStyleSheet("color: orange; font-weight: bold; padding: 10px;")
            layout.addWidget(warning_label)
        
        # PCAP Analysis Section
        pcap_group = QGroupBox("PCAP File Analysis")
        pcap_layout = QVBoxLayout(pcap_group)
        
        pcap_file_layout = QHBoxLayout()
        self.pcap_file_path = QLineEdit()
        self.pcap_file_path.setPlaceholderText("Select PCAP file...")
        self.select_pcap_btn = QPushButton("Browse")
        
        pcap_file_layout.addWidget(QLabel("PCAP File:"))
        pcap_file_layout.addWidget(self.pcap_file_path)
        pcap_file_layout.addWidget(self.select_pcap_btn)
        
        pcap_layout.addLayout(pcap_file_layout)
        
        # Live Capture Section
        live_group = QGroupBox("Live Network Monitoring")
        live_layout = QVBoxLayout(live_group)
        
        interface_layout = QHBoxLayout()
        self.interface_combo = QComboBox()
        self.refresh_interfaces_btn = QPushButton("Refresh")
        self.packet_count_spin = QSpinBox()
        self.packet_count_spin.setRange(10, 10000)
        self.packet_count_spin.setValue(100)
        
        interface_layout.addWidget(QLabel("Interface:"))
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addWidget(self.refresh_interfaces_btn)
        interface_layout.addWidget(QLabel("Packets:"))
        interface_layout.addWidget(self.packet_count_spin)
        
        live_layout.addLayout(interface_layout)
        
        # Protocol Selection
        protocol_group = QGroupBox("Protocol Selection")
        protocol_layout = QVBoxLayout(protocol_group)
        
        # Create checkboxes for protocols
        protocol_grid = QHBoxLayout()
        
        left_protocols = QVBoxLayout()
        self.http_basic_cb = QCheckBox("HTTP Basic Auth")
        self.ntlm_cb = QCheckBox("NTLM")
        self.kerberos_cb = QCheckBox("Kerberos")
        self.ftp_cb = QCheckBox("FTP")
        
        left_protocols.addWidget(self.http_basic_cb)
        left_protocols.addWidget(self.ntlm_cb)
        left_protocols.addWidget(self.kerberos_cb)
        left_protocols.addWidget(self.ftp_cb)
        
        right_protocols = QVBoxLayout()
        self.smtp_cb = QCheckBox("SMTP")
        self.pop3_cb = QCheckBox("POP3")
        self.imap_cb = QCheckBox("IMAP")
        self.snmp_cb = QCheckBox("SNMP")
        self.telnet_cb = QCheckBox("Telnet")
        
        right_protocols.addWidget(self.smtp_cb)
        right_protocols.addWidget(self.pop3_cb)
        right_protocols.addWidget(self.imap_cb)
        right_protocols.addWidget(self.snmp_cb)
        right_protocols.addWidget(self.telnet_cb)
        
        protocol_grid.addLayout(left_protocols)
        protocol_grid.addLayout(right_protocols)
        protocol_layout.addLayout(protocol_grid)
        
        # Set default selections
        self.http_basic_cb.setChecked(True)
        self.ntlm_cb.setChecked(True)
        self.kerberos_cb.setChecked(True)
        self.ftp_cb.setChecked(True)
        self.smtp_cb.setChecked(True)
        
        # Control buttons
        network_control_layout = QHBoxLayout()
        self.start_pcap_scan_btn = QPushButton("Analyze PCAP")
        self.start_live_capture_btn = QPushButton("Start Live Capture")
        self.stop_capture_btn = QPushButton("Stop Capture")
        self.export_network_results_btn = QPushButton("Export Results")
        
        self.stop_capture_btn.setEnabled(False)
        
        network_control_layout.addWidget(self.start_pcap_scan_btn)
        network_control_layout.addWidget(self.start_live_capture_btn)
        network_control_layout.addWidget(self.stop_capture_btn)
        network_control_layout.addWidget(self.export_network_results_btn)
        network_control_layout.addStretch()
        
        # Progress and status
        self.network_progress_bar = QProgressBar()
        self.network_status_label = QLabel("Ready")
        
        # Add all sections
        layout.addWidget(pcap_group)
        layout.addWidget(live_group)
        layout.addWidget(protocol_group)
        layout.addLayout(network_control_layout)
        layout.addWidget(self.network_progress_bar)
        layout.addWidget(self.network_status_label)
        layout.addStretch()
        
        # Connect signals
        self.select_pcap_btn.clicked.connect(self.select_pcap_file)
        self.refresh_interfaces_btn.clicked.connect(self.refresh_network_interfaces)
        self.start_pcap_scan_btn.clicked.connect(self.start_pcap_analysis)
        self.start_live_capture_btn.clicked.connect(self.start_live_capture)
        self.stop_capture_btn.clicked.connect(self.stop_network_capture)
        self.export_network_results_btn.clicked.connect(self.export_network_results)
        
        # Initialize interfaces
        self.refresh_network_interfaces()
        
        self.tab_widget.addTab(network_tab, "Network Scanner")
        
    def create_repository_scan_tab(self):
        """Create repository scanning tab"""
        repo_tab = QWidget()
        layout = QVBoxLayout(repo_tab)
        
        if not REPO_SCANNER_AVAILABLE:
            warning_label = QLabel("⚠️ Repository scanner module not available")
            warning_label.setStyleSheet("color: orange; font-weight: bold; padding: 10px;")
            layout.addWidget(warning_label)
        
        # Directory Selection
        dir_group = QGroupBox("Directory Selection")
        dir_layout = QVBoxLayout(dir_group)
        
        dir_selection_layout = QHBoxLayout()
        self.repo_scan_path = QLineEdit()
        self.repo_scan_path.setPlaceholderText("Select directory to scan...")
        self.select_repo_dir_btn = QPushButton("Browse")
        
        dir_selection_layout.addWidget(QLabel("Directory:"))
        dir_selection_layout.addWidget(self.repo_scan_path)
        dir_selection_layout.addWidget(self.select_repo_dir_btn)
        
        dir_layout.addLayout(dir_selection_layout)
        
        # Scan Options
        repo_options_group = QGroupBox("Scan Options")
        repo_options_layout = QVBoxLayout(repo_options_group)
        
        self.scan_common_locations_cb = QCheckBox("Scan Common Credential Locations")
        self.scan_common_locations_cb.setChecked(True)
        self.recursive_scan_cb = QCheckBox("Recursive Directory Scan")
        self.recursive_scan_cb.setChecked(True)
        
        repo_options_layout.addWidget(self.scan_common_locations_cb)
        repo_options_layout.addWidget(self.recursive_scan_cb)
        
        # Control buttons
        repo_control_layout = QHBoxLayout()
        self.start_repo_scan_btn = QPushButton("Start Repository Scan")
        self.export_repo_results_btn = QPushButton("Export Results")
        
        repo_control_layout.addWidget(self.start_repo_scan_btn)
        repo_control_layout.addWidget(self.export_repo_results_btn)
        repo_control_layout.addStretch()
        
        # Progress and status
        self.repo_progress_bar = QProgressBar()
        self.repo_status_label = QLabel("Ready")
        
        # Add sections
        layout.addWidget(dir_group)
        layout.addWidget(repo_options_group)
        layout.addLayout(repo_control_layout)
        layout.addWidget(self.repo_progress_bar)
        layout.addWidget(self.repo_status_label)
        layout.addStretch()
        
        # Connect signals
        self.select_repo_dir_btn.clicked.connect(self.select_repository_directory)
        self.start_repo_scan_btn.clicked.connect(self.start_repository_scan)
        self.export_repo_results_btn.clicked.connect(self.export_repository_results)
        
        self.tab_widget.addTab(repo_tab, "Repository Scanner")
        
    def create_results_tab(self):
        """Create results display tab"""
        results_tab = QWidget()
        layout = QVBoxLayout(results_tab)
        
        # Create sub-tabs for different result types
        self.results_tab_widget = QTabWidget()
        layout.addWidget(self.results_tab_widget)
        
        # File scan results
        self.file_results_table = QTableWidget()
        self.file_results_table.setColumnCount(3)
        self.file_results_table.setHorizontalHeaderLabels(["File Path", "Type", "Content"])
        self.file_results_table.horizontalHeader().setStretchLastSection(True)
        self.results_tab_widget.addTab(self.file_results_table, "File Results")
        
        # Network scan results
        self.network_results_table = QTableWidget()
        self.network_results_table.setColumnCount(4)
        self.network_results_table.setHorizontalHeaderLabels(["Source", "Protocol", "Type", "Content"])
        self.network_results_table.horizontalHeader().setStretchLastSection(True)
        self.results_tab_widget.addTab(self.network_results_table, "Network Results")
        
        # Repository scan results
        self.repo_results_table = QTableWidget()
        self.repo_results_table.setColumnCount(5)
        self.repo_results_table.setHorizontalHeaderLabels(["File Path", "Repository Type", "Credential Type", "Content", "Confidence"])
        self.repo_results_table.horizontalHeader().setStretchLastSection(True)
        self.results_tab_widget.addTab(self.repo_results_table, "Repository Results")
        
        # Summary section
        summary_layout = QHBoxLayout()
        self.file_results_count = QLabel("File Results: 0")
        self.network_results_count = QLabel("Network Results: 0")
        self.repo_results_count = QLabel("Repository Results: 0")
        
        summary_layout.addWidget(self.file_results_count)
        summary_layout.addWidget(self.network_results_count)
        summary_layout.addWidget(self.repo_results_count)
        summary_layout.addStretch()
        
        layout.addLayout(summary_layout)
        
        self.tab_widget.addTab(results_tab, "Results")
        
    def create_settings_tab(self):
        """Create settings tab"""
        settings_tab = QWidget()
        layout = QVBoxLayout(settings_tab)
        
        # File Extensions
        ext_group = QGroupBox("File Extensions to Scan")
        ext_layout = QVBoxLayout(ext_group)
        
        self.file_extensions = QLineEdit()
        self.file_extensions.setText(".txt,.log,.csv,.json,.xml,.html,.php,.py,.js,.config")
        self.file_extensions.setPlaceholderText("Comma-separated file extensions")
        
        ext_layout.addWidget(QLabel("Extensions:"))
        ext_layout.addWidget(self.file_extensions)
        
        # Export Settings
        export_group = QGroupBox("Export Settings")
        export_layout = QVBoxLayout(export_group)
        
        self.export_format_combo = QComboBox()
        self.export_format_combo.addItems(["Text", "JSON", "CSV"])
        
        export_layout.addWidget(QLabel("Export Format:"))
        export_layout.addWidget(self.export_format_combo)
        
        # About section
        about_group = QGroupBox("About")
        about_layout = QVBoxLayout(about_group)
        
        about_text = QTextBrowser()
        about_text.setMaximumHeight(200)
        about_text.setHtml("""
        <h3>Enhanced Payment & Credential Scanner v2.0</h3>
        <p><b>Features:</b></p>
        <ul>
        <li>File-based scanning for payment information</li>
        <li>Network traffic analysis (PCAP files and live capture)</li>
        <li>Repository scanning for credential storage locations</li>
        <li>Protocol-specific credential extraction</li>
        <li>Multiple export formats</li>
        </ul>
        <p><b>Security Note:</b> This tool is designed for legitimate security auditing and compliance purposes only.</p>
        """)
        
        about_layout.addWidget(about_text)
        
        layout.addWidget(ext_group)
        layout.addWidget(export_group)
        layout.addWidget(about_group)
        layout.addStretch()
        
        self.tab_widget.addTab(settings_tab, "Settings")
    
    # Method implementations
    def select_files(self):
        """Select individual files for scanning"""
        files, _ = QFileDialog.getOpenFileNames(
            self, 
            "Select Files to Scan",
            "",
            "All Files (*.*)"
        )
        
        if files:
            self.selected_files_list.clear()
            for file in files:
                self.selected_files_list.addItem(file)

    def select_folder(self):
        """Select folder for batch scanning"""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        
        if folder:
            # Get file extensions from settings
            extensions = [ext.strip() for ext in self.file_extensions.text().split(',')]
            
            files = []
            for root, dirs, filenames in os.walk(folder):
                for filename in filenames:
                    if any(filename.lower().endswith(ext.lower()) for ext in extensions):
                        files.append(os.path.join(root, filename))
            
            self.selected_files_list.clear()
            for file in files:
                self.selected_files_list.addItem(file)

    def start_file_scan(self):
        """Start file scanning process"""
        files = [self.selected_files_list.item(i).text() 
                 for i in range(self.selected_files_list.count())]
        
        if not files:
            QMessageBox.warning(self, "Warning", "Please select files to scan first.")
            return
        
        # Get scan options
        scan_options = {
            'credit_cards': self.credit_cards_cb.isChecked(),
            'names': self.names_cb.isChecked(),
            'emails': self.emails_cb.isChecked(),
            'phones': self.phones_cb.isChecked()
        }
        
        # Start scanning thread
        self.file_scan_thread = FileScanThread(files, scan_options)
        self.file_scan_thread.progress_updated.connect(self.file_progress_bar.setValue)
        self.file_scan_thread.result_found.connect(self.add_file_result)
        self.file_scan_thread.scan_completed.connect(self.file_scan_completed)
        
        self.start_file_scan_btn.setEnabled(False)
        self.file_progress_bar.setValue(0)
        self.statusBar().showMessage("Scanning files...")
        
        self.file_scan_thread.start()

    def add_file_result(self, file_path, info_type, content):
        """Add result to file results table"""
        self.scan_results.append((file_path, info_type, content))
        
        row = self.file_results_table.rowCount()
        self.file_results_table.insertRow(row)
        
        self.file_results_table.setItem(row, 0, QTableWidgetItem(file_path))
        self.file_results_table.setItem(row, 1, QTableWidgetItem(info_type))
        self.file_results_table.setItem(row, 2, QTableWidgetItem(content))
        
        # Update count
        self.file_results_count.setText(f"File Results: {len(self.scan_results)}")

    def file_scan_completed(self):
        """Handle file scan completion"""
        self.start_file_scan_btn.setEnabled(True)
        self.statusBar().showMessage(f"File scan completed. Found {len(self.scan_results)} results.")
        
        if self.scan_results:
            QMessageBox.information(
                self, 
                "Scan Complete", 
                f"File scan completed!\nFound {len(self.scan_results)} potential matches."
            )

    def export_file_results(self):
        """Export file scan results"""
        if not self.scan_results:
            QMessageBox.warning(self, "Warning", "No results to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "Export File Results",
            f"file_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    data = [{'file_path': r[0], 'type': r[1], 'content': r[2]} for r in self.scan_results]
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['File Path', 'Type', 'Content'])
                        writer.writerows(self.scan_results)
                else:
                    with open(filename, 'w') as f:
                        f.write("File Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        for file_path, info_type, content in self.scan_results:
                            f.write(f"File: {file_path}\n")
                            f.write(f"Type: {info_type}\n")
                            f.write(f"Content: {content}\n")
                            f.write("-" * 30 + "\n")
                
                QMessageBox.information(self, "Success", f"Results exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")

    def select_pcap_file(self):
        """Select PCAP file for analysis"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*.*)"
        )
        
        if filename:
            self.pcap_file_path.setText(filename)

    def refresh_network_interfaces(self):
        """Refresh network interfaces list"""
        self.interface_combo.clear()
        
        if NETWORK_AVAILABLE:
            try:
                analyzer = NetworkAnalyzer()
                interfaces = analyzer.get_network_interfaces()
                self.interface_combo.addItems(interfaces)
            except Exception as e:
                print(f"Error getting interfaces: {e}")
                self.interface_combo.addItem("No interfaces available")
        else:
            self.interface_combo.addItem("Network analysis not available")

    def get_selected_protocols(self):
        """Get list of selected protocols"""
        protocols = []
        if self.http_basic_cb.isChecked():
            protocols.append('HTTP Basic Auth')
        if self.ntlm_cb.isChecked():
            protocols.append('NTLM')
        if self.kerberos_cb.isChecked():
            protocols.append('Kerberos')
        if self.ftp_cb.isChecked():
            protocols.append('FTP')
        if self.smtp_cb.isChecked():
            protocols.append('SMTP')
        if self.pop3_cb.isChecked():
            protocols.append('POP3')
        if self.imap_cb.isChecked():
            protocols.append('IMAP')
        if self.snmp_cb.isChecked():
            protocols.append('SNMP')
        if self.telnet_cb.isChecked():
            protocols.append('Telnet')
        return protocols

    def start_pcap_analysis(self):
        """Start PCAP file analysis"""
        pcap_file = self.pcap_file_path.text().strip()
        
        if not pcap_file:
            QMessageBox.warning(self, "Warning", "Please select a PCAP file first.")
            return
        
        if not os.path.exists(pcap_file):
            QMessageBox.warning(self, "Warning", "Selected PCAP file does not exist.")
            return
        
        protocols = self.get_selected_protocols()
        if not protocols:
            QMessageBox.warning(self, "Warning", "Please select at least one protocol to analyze.")
            return
        
        # Start network scan thread
        self.network_scan_thread = NetworkScanThread('pcap', pcap_file, protocols)
        self.network_scan_thread.progress_updated.connect(self.network_progress_bar.setValue)
        self.network_scan_thread.result_found.connect(self.add_network_result)
        self.network_scan_thread.scan_completed.connect(self.network_scan_completed)
        self.network_scan_thread.status_updated.connect(self.network_status_label.setText)
        
        self.start_pcap_scan_btn.setEnabled(False)
        self.network_progress_bar.setValue(0)
        
        self.network_scan_thread.start()

    def start_live_capture(self):
        """Start live network capture"""
        interface = self.interface_combo.currentText()
        
        if not interface or interface == "No interfaces available":
            QMessageBox.warning(self, "Warning", "Please select a valid network interface.")
            return
        
        protocols = self.get_selected_protocols()
        if not protocols:
            QMessageBox.warning(self, "Warning", "Please select at least one protocol to analyze.")
            return
        
        packet_count = self.packet_count_spin.value()
        options = {'packet_count': packet_count}
        
        # Start network scan thread
        self.network_scan_thread = NetworkScanThread('live', interface, protocols, options)
        self.network_scan_thread.progress_updated.connect(self.network_progress_bar.setValue)
        self.network_scan_thread.result_found.connect(self.add_network_result)
        self.network_scan_thread.scan_completed.connect(self.network_scan_completed)
        self.network_scan_thread.status_updated.connect(self.network_status_label.setText)
        
        self.start_live_capture_btn.setEnabled(False)
        self.stop_capture_btn.setEnabled(True)
        self.network_progress_bar.setValue(0)
        
        self.network_scan_thread.start()

    def stop_network_capture(self):
        """Stop network capture"""
        if hasattr(self, 'network_scan_thread') and self.network_scan_thread.isRunning():
            self.network_scan_thread.terminate()
            self.network_scan_thread.wait()
        
        self.start_live_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        self.network_status_label.setText("Capture stopped")

    def add_network_result(self, source, protocol, cred_type, content):
        """Add result to network results table"""
        self.network_results.append((source, protocol, cred_type, content))
        
        row = self.network_results_table.rowCount()
        self.network_results_table.insertRow(row)
        
        self.network_results_table.setItem(row, 0, QTableWidgetItem(source))
        self.network_results_table.setItem(row, 1, QTableWidgetItem(protocol))
        self.network_results_table.setItem(row, 2, QTableWidgetItem(cred_type))
        self.network_results_table.setItem(row, 3, QTableWidgetItem(content))
        
        # Update count
        self.network_results_count.setText(f"Network Results: {len(self.network_results)}")

    def network_scan_completed(self):
        """Handle network scan completion"""
        self.start_pcap_scan_btn.setEnabled(True)
        self.start_live_capture_btn.setEnabled(True)
        self.stop_capture_btn.setEnabled(False)
        
        self.statusBar().showMessage(f"Network scan completed. Found {len(self.network_results)} results.")
        
        if self.network_results:
            QMessageBox.information(
                self, 
                "Scan Complete", 
                f"Network scan completed!\nFound {len(self.network_results)} credential entries."
            )

    def export_network_results(self):
        """Export network scan results"""
        if not self.network_results:
            QMessageBox.warning(self, "Warning", "No network results to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "Export Network Results",
            f"network_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    data = [{'source': r[0], 'protocol': r[1], 'type': r[2], 'content': r[3]} for r in self.network_results]
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Source', 'Protocol', 'Type', 'Content'])
                        writer.writerows(self.network_results)
                else:
                    with open(filename, 'w') as f:
                        f.write("Network Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        for source, protocol, cred_type, content in self.network_results:
                            f.write(f"Source: {source}\n")
                            f.write(f"Protocol: {protocol}\n")
                            f.write(f"Type: {cred_type}\n")
                            f.write(f"Content: {content}\n")
                            f.write("-" * 30 + "\n")
                
                QMessageBox.information(self, "Success", f"Results exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")

    def select_repository_directory(self):
        """Select directory for repository scanning"""
        directory = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        
        if directory:
            self.repo_scan_path.setText(directory)

    def start_repository_scan(self):
        """Start repository scanning process"""
        scan_common = self.scan_common_locations_cb.isChecked()
        scan_path = self.repo_scan_path.text().strip()
        
        if not scan_common and not scan_path:
            QMessageBox.warning(self, "Warning", "Please select a directory or enable common locations scan.")
            return
        
        if scan_path and not os.path.exists(scan_path):
            QMessageBox.warning(self, "Warning", "Selected directory does not exist.")
            return
        
        # Start repository scan thread
        self.repo_scan_thread = RepositoryScanThread(scan_path, scan_common)
        self.repo_scan_thread.progress_updated.connect(self.repo_progress_bar.setValue)
        self.repo_scan_thread.result_found.connect(self.add_repository_result)
        self.repo_scan_thread.scan_completed.connect(self.repository_scan_completed)
        self.repo_scan_thread.status_updated.connect(self.repo_status_label.setText)
        
        self.start_repo_scan_btn.setEnabled(False)
        self.repo_progress_bar.setValue(0)
        
        self.repo_scan_thread.start()

    def add_repository_result(self, file_path, repo_type, cred_type, content, confidence):
        """Add result to repository results table"""
        self.repository_results.append((file_path, repo_type, cred_type, content, confidence))
        
        row = self.repo_results_table.rowCount()
        self.repo_results_table.insertRow(row)
        
        self.repo_results_table.setItem(row, 0, QTableWidgetItem(file_path))
        self.repo_results_table.setItem(row, 1, QTableWidgetItem(repo_type))
        self.repo_results_table.setItem(row, 2, QTableWidgetItem(cred_type))
        self.repo_results_table.setItem(row, 3, QTableWidgetItem(content))
        
        # Color code by confidence
        confidence_item = QTableWidgetItem(confidence.upper())
        if confidence == 'high':
            confidence_item.setBackground(Qt.GlobalColor.red)
        elif confidence == 'medium':
            confidence_item.setBackground(Qt.GlobalColor.yellow)
        else:
            confidence_item.setBackground(Qt.GlobalColor.lightGray)
        
        self.repo_results_table.setItem(row, 4, confidence_item)
        
        # Update count
        self.repo_results_count.setText(f"Repository Results: {len(self.repository_results)}")

    def repository_scan_completed(self):
        """Handle repository scan completion"""
        self.start_repo_scan_btn.setEnabled(True)
        self.statusBar().showMessage(f"Repository scan completed. Found {len(self.repository_results)} results.")
        
        if self.repository_results:
            QMessageBox.information(
                self, 
                "Scan Complete", 
                f"Repository scan completed!\nFound {len(self.repository_results)} potential credential repositories."
            )

    def export_repository_results(self):
        """Export repository scan results"""
        if not self.repository_results:
            QMessageBox.warning(self, "Warning", "No repository results to export.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "Export Repository Results",
            f"repository_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON Files (*.json);;CSV Files (*.csv)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    data = [{'file_path': r[0], 'repo_type': r[1], 'cred_type': r[2], 'content': r[3], 'confidence': r[4]} 
                            for r in self.repository_results]
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['File Path', 'Repository Type', 'Credential Type', 'Content', 'Confidence'])
                        writer.writerows(self.repository_results)
                else:
                    with open(filename, 'w') as f:
                        f.write("Repository Scan Results\n")
                        f.write("=" * 50 + "\n\n")
                        
                        # Group by confidence
                        high_conf = [r for r in self.repository_results if r[4] == 'high']
                        medium_conf = [r for r in self.repository_results if r[4] == 'medium']
                        low_conf = [r for r in self.repository_results if r[4] == 'low']
                        
                        for conf_level, results in [('HIGH', high_conf), ('MEDIUM', medium_conf), ('LOW', low_conf)]:
                            if results:
                                f.write(f"\n{conf_level} CONFIDENCE RESULTS:\n")
                                f.write("-" * 30 + "\n")
                                for file_path, repo_type, cred_type, content, confidence in results:
                                    f.write(f"File: {file_path}\n")
                                    f.write(f"Repository Type: {repo_type}\n")
                                    f.write(f"Credential Type: {cred_type}\n")
                                    f.write(f"Content: {content}\n")
                                    f.write("-" * 20 + "\n")
                
                QMessageBox.information(self, "Success", f"Results exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export results: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EnhancedScannerApp()
    window.show()
    sys.exit(app.exec())
