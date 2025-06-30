#!/usr/bin/env python3
"""
Enhanced Scanner Methods
Method implementations for the Enhanced Payment & Credential Scanner
"""

# This file contains the method implementations that should be added to the EnhancedScannerApp class

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
