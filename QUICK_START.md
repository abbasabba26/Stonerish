# 🚀 Quick Start Guide - Enhanced Payment & Credential Scanner v2.0

## ⚡ 5-Minute Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Test Installation
```bash
python test_installation.py
```

### 3. Launch Application
```bash
python enhanced_scanner.py
```

## 🎯 First Scan Examples

### File Scanning (Easiest)
1. Open **File Scanner** tab
2. Click **Select Folder** → Choose a test directory
3. Click **Start File Scan**
4. View results in **Results** tab

### Repository Scanning (Recommended)
1. Open **Repository Scanner** tab
2. Check **Scan Common Credential Locations**
3. Click **Start Repository Scan**
4. Check **Repository Results** for findings

### Network Analysis (Advanced)
1. Open **Network Scanner** tab
2. For PCAP: Click **Browse** → Select .pcap file
3. For Live: Select network interface
4. Choose protocols to analyze
5. Click **Analyze PCAP** or **Start Live Capture**

## 🔧 Common Issues & Solutions

### ❌ "Network analysis not available"
```bash
pip install scapy
```

### ❌ "Permission denied" (Network capture)
- **Windows**: Run as Administrator
- **Linux/Mac**: Run with `sudo`

### ❌ "PyQt6 not found"
```bash
pip install PyQt6
```

### ❌ "Repository scanner not available"
```bash
pip install pyyaml configparser
```

## 📊 Understanding Results

### Confidence Levels
- 🔴 **HIGH**: Very likely to be real credentials
- 🟡 **MEDIUM**: Possible credentials, needs verification
- ⚪ **LOW**: Pattern matches, likely false positives

### Export Options
- **TXT**: Human-readable format
- **JSON**: Machine-readable format
- **CSV**: Spreadsheet-compatible format

## 🛡️ Security Best Practices

### ✅ Do
- Use on systems you own or have permission to test
- Secure exported results
- Follow local laws and regulations
- Test in isolated environments first

### ❌ Don't
- Scan systems without authorization
- Share discovered credentials
- Use on production networks without approval
- Ignore privacy regulations

## 🎓 Learning Path

### Beginner
1. Start with **File Scanner** on test files
2. Try **Repository Scanner** on safe directories
3. Practice with export features

### Intermediate
1. Analyze sample PCAP files
2. Experiment with protocol selection
3. Compare different scan types

### Advanced
1. Live network monitoring (with proper permissions)
2. Custom configuration files
3. Integration with security workflows

## 📞 Need Help?

### Check Installation
```bash
python test_installation.py
```

### Verify Dependencies
```bash
pip list | grep -E "(PyQt6|scapy|pyyaml)"
```

### Test Basic Functionality
```bash
python -c "from enhanced_scanner import EnhancedScannerApp; print('✅ Ready to go!')"
```

## 🎉 You're Ready!

The Enhanced Payment & Credential Scanner is now ready for use. Start with file scanning to get familiar with the interface, then explore the advanced network and repository features.

**Remember**: Always use responsibly and with proper authorization! 🔒
