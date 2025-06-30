# 🚀 Deployment Guide - Enhanced Payment & Credential Scanner v2.0

## 📋 Deployment Options

### 1. 🖥️ Local Desktop Application (Recommended)
### 2. 🐳 Docker Container
### 3. 🌐 Web Application (Flask/FastAPI)
### 4. 📦 Standalone Executable
### 5. ☁️ Cloud Deployment

---

## 1. 🖥️ Local Desktop Application

### Quick Deployment
```bash
# Clone the repository
git clone https://github.com/abbasabba26/Stonerish.git
cd Stonerish

# Install dependencies
pip install -r requirements.txt

# Test installation
python test_installation.py

# Launch application
python enhanced_scanner.py
```

### Production Setup
```bash
# Create virtual environment
python -m venv scanner_env
source scanner_env/bin/activate  # Linux/Mac
# scanner_env\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Create desktop shortcut (optional)
python create_shortcut.py
```

### System Requirements
- **Python**: 3.7+
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 500MB for application + space for results
- **Network**: Admin privileges for live capture
- **OS**: Windows 10+, macOS 10.14+, Ubuntu 18.04+

---

## 2. 🐳 Docker Container

### Create Dockerfile
```dockerfile
FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create non-root user for security
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

# Expose port for web interface (if added)
EXPOSE 8080

# Default command
CMD ["python", "enhanced_scanner.py"]
```

### Docker Compose Setup
```yaml
version: '3.8'
services:
  scanner:
    build: .
    container_name: credential_scanner
    volumes:
      - ./data:/app/data
      - ./results:/app/results
    environment:
      - DISPLAY=${DISPLAY}
    network_mode: host
    privileged: true  # Required for network capture
    stdin_open: true
    tty: true
```

### Build and Run
```bash
# Build image
docker build -t credential-scanner .

# Run container
docker run -it --privileged --net=host \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/results:/app/results \
  credential-scanner

# With GUI support (Linux)
docker run -it --privileged --net=host \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  -v $(pwd)/data:/app/data \
  credential-scanner
```

---

## 3. 🌐 Web Application

### Flask Web Interface
```python
# web_app.py
from flask import Flask, render_template, request, jsonify, send_file
from enhanced_scanner import EnhancedScannerApp
import json
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    # File scanning endpoint
    pass

@app.route('/api/scan/network', methods=['POST'])
def scan_network():
    # Network scanning endpoint
    pass

@app.route('/api/results/<scan_id>')
def get_results(scan_id):
    # Get scan results
    pass

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
```

### Web Deployment with Gunicorn
```bash
# Install web dependencies
pip install flask gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8080 web_app:app

# With nginx reverse proxy
# /etc/nginx/sites-available/scanner
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 4. 📦 Standalone Executable

### Using PyInstaller
```bash
# Install PyInstaller
pip install pyinstaller

# Create executable
pyinstaller --onefile --windowed \
  --add-data "network_analyzer.py:." \
  --add-data "repository_scanner.py:." \
  --hidden-import PyQt6 \
  --hidden-import scapy \
  enhanced_scanner.py

# The executable will be in dist/
```

### Advanced PyInstaller Setup
```python
# scanner.spec
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['enhanced_scanner.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('network_analyzer.py', '.'),
        ('repository_scanner.py', '.'),
        ('README.md', '.'),
        ('QUICK_START.md', '.')
    ],
    hiddenimports=[
        'PyQt6',
        'scapy',
        'yaml',
        'configparser'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CredentialScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='scanner_icon.ico'
)
```

### Build Executable
```bash
# Build from spec file
pyinstaller scanner.spec

# Test the executable
./dist/CredentialScanner
```

---

## 5. ☁️ Cloud Deployment

### AWS EC2 Deployment
```bash
# Launch EC2 instance (Ubuntu 20.04)
# Connect via SSH

# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and dependencies
sudo apt install python3 python3-pip python3-venv -y

# Clone and setup
git clone https://github.com/abbasabba26/Stonerish.git
cd Stonerish
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install system dependencies for network capture
sudo apt install libpcap-dev tcpdump -y

# Setup systemd service
sudo cp scanner.service /etc/systemd/system/
sudo systemctl enable scanner
sudo systemctl start scanner
```

### Systemd Service File
```ini
# scanner.service
[Unit]
Description=Enhanced Credential Scanner
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/Stonerish
Environment=PATH=/home/ubuntu/Stonerish/venv/bin
ExecStart=/home/ubuntu/Stonerish/venv/bin/python enhanced_scanner.py
Restart=always

[Install]
WantedBy=multi-user.target
```

### Google Cloud Platform
```bash
# Create VM instance
gcloud compute instances create scanner-vm \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --machine-type=e2-medium \
  --zone=us-central1-a

# SSH and setup
gcloud compute ssh scanner-vm --zone=us-central1-a
# Follow same setup as AWS
```

### Azure Deployment
```bash
# Create resource group
az group create --name ScannerRG --location eastus

# Create VM
az vm create \
  --resource-group ScannerRG \
  --name ScannerVM \
  --image UbuntuLTS \
  --admin-username azureuser \
  --generate-ssh-keys

# SSH and setup
az vm run-command invoke \
  --resource-group ScannerRG \
  --name ScannerVM \
  --command-id RunShellScript \
  --scripts @setup_script.sh
```

---

## 🔧 Configuration Management

### Environment Variables
```bash
# .env file
SCANNER_LOG_LEVEL=INFO
SCANNER_MAX_FILE_SIZE=100MB
SCANNER_EXPORT_DIR=./results
SCANNER_TEMP_DIR=./temp
NETWORK_CAPTURE_TIMEOUT=300
REPOSITORY_SCAN_DEPTH=5
```

### Configuration File
```yaml
# config.yaml
scanner:
  log_level: INFO
  max_file_size: 104857600  # 100MB
  export_directory: "./results"
  temp_directory: "./temp"

network:
  capture_timeout: 300
  max_packets: 10000
  interfaces:
    - eth0
    - wlan0

repository:
  scan_depth: 5
  common_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.config"

protocols:
  enabled:
    - "HTTP Basic Auth"
    - "NTLM"
    - "Kerberos"
    - "FTP"
    - "SMTP"
```

---

## 🛡️ Security Considerations

### Network Security
```bash
# Firewall rules (UFW)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8080/tcp  # Web interface (if used)
sudo ufw enable

# Restrict network capture to specific interfaces
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
```

### File Permissions
```bash
# Set proper permissions
chmod 755 enhanced_scanner.py
chmod 644 *.py
chmod 600 config.yaml
chmod 700 results/

# Create dedicated user
sudo useradd -m -s /bin/bash scanner
sudo usermod -aG sudo scanner
```

### SSL/TLS (for web deployment)
```bash
# Generate SSL certificate
sudo apt install certbot
sudo certbot --nginx -d your-domain.com

# Or use Let's Encrypt
sudo certbot certonly --standalone -d your-domain.com
```

---

## 📊 Monitoring & Logging

### Logging Setup
```python
# logging_config.py
import logging
import logging.handlers

def setup_logging():
    logger = logging.getLogger('scanner')
    logger.setLevel(logging.INFO)
    
    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        'scanner.log', maxBytes=10485760, backupCount=5
    )
    file_handler.setFormatter(
        logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    
    logger.addHandler(file_handler)
    return logger
```

### Health Check Script
```python
# health_check.py
import requests
import sys

def check_health():
    try:
        # Check if application is running
        response = requests.get('http://localhost:8080/health', timeout=5)
        if response.status_code == 200:
            print("✅ Application is healthy")
            return True
    except:
        print("❌ Application is not responding")
        return False

if __name__ == "__main__":
    if not check_health():
        sys.exit(1)
```

---

## 🚀 Deployment Automation

### Deployment Script
```bash
#!/bin/bash
# deploy.sh

set -e

echo "🚀 Deploying Enhanced Credential Scanner..."

# Update code
git pull origin main

# Install/update dependencies
pip install -r requirements.txt

# Run tests
python test_installation.py

# Restart service (if using systemd)
sudo systemctl restart scanner

# Health check
sleep 5
python health_check.py

echo "✅ Deployment completed successfully!"
```

### CI/CD with GitHub Actions
```yaml
# .github/workflows/deploy.yml
name: Deploy Scanner

on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run tests
      run: |
        python test_installation.py
    
    - name: Deploy to server
      run: |
        # Add deployment commands here
        echo "Deploying to production..."
```

---

## 📱 Platform-Specific Instructions

### Windows Deployment
```powershell
# PowerShell script
# Install Python from Microsoft Store or python.org
# Install Git for Windows

# Clone and setup
git clone https://github.com/abbasabba26/Stonerish.git
cd Stonerish
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Create batch file for easy launching
echo @echo off > launch_scanner.bat
echo cd /d "%~dp0" >> launch_scanner.bat
echo venv\Scripts\activate >> launch_scanner.bat
echo python enhanced_scanner.py >> launch_scanner.bat
echo pause >> launch_scanner.bat
```

### macOS Deployment
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python

# Clone and setup
git clone https://github.com/abbasabba26/Stonerish.git
cd Stonerish
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create app bundle (optional)
pip install py2app
python setup.py py2app
```

### Linux (Ubuntu/Debian)
```bash
# Install dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv git libpcap-dev -y

# Clone and setup
git clone https://github.com/abbasabba26/Stonerish.git
cd Stonerish
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Create desktop entry
cat > ~/.local/share/applications/credential-scanner.desktop << EOF
[Desktop Entry]
Name=Credential Scanner
Comment=Enhanced Payment & Credential Scanner
Exec=/path/to/Stonerish/venv/bin/python /path/to/Stonerish/enhanced_scanner.py
Icon=/path/to/Stonerish/icon.png
Terminal=false
Type=Application
Categories=Security;
EOF
```

---

## 🎯 Quick Deployment Summary

### For End Users (Simplest)
```bash
git clone https://github.com/abbasabba26/Stonerish.git
cd Stonerish
pip install -r requirements.txt
python enhanced_scanner.py
```

### For Production (Recommended)
```bash
# Use Docker
docker build -t credential-scanner .
docker run -it --privileged credential-scanner

# Or systemd service
sudo systemctl enable scanner
sudo systemctl start scanner
```

### For Distribution
```bash
# Create executable
pyinstaller --onefile enhanced_scanner.py
# Distribute the dist/ folder
```

Choose the deployment method that best fits your needs! 🚀
