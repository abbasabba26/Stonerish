#!/usr/bin/env python3
"""
Enhanced Payment & Credential Scanner - One-Click Installer
Downloads and sets up the complete scanner application
"""

import os
import sys
import subprocess
import urllib.request
import zipfile
import tempfile
from pathlib import Path

def print_status(message):
    print(f"🔄 {message}")

def print_success(message):
    print(f"✅ {message}")

def print_error(message):
    print(f"❌ {message}")

def check_python_version():
    """Check if Python version is compatible"""
    if sys.version_info < (3, 7):
        print_error("Python 3.7 or higher is required")
        print("Please upgrade Python and try again")
        return False
    print_success(f"Python {sys.version.split()[0]} detected")
    return True

def install_pip_packages():
    """Install required packages"""
    packages = [
        "PyQt6>=6.4.0",
        "scapy>=2.5.0", 
        "pyyaml>=6.0"
    ]
    
    print_status("Installing required packages...")
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print_success(f"Installed {package}")
        except subprocess.CalledProcessError:
            print_error(f"Failed to install {package}")
            print("You may need to install manually with: pip install " + package)

def download_scanner():
    """Download the scanner from GitHub"""
    print_status("Downloading Enhanced Scanner...")
    
    # GitHub repository URL
    repo_url = "https://github.com/abbasabba26/Stonerish/archive/refs/heads/codegen-bot/network-analysis-enhancement-1751191025.zip"
    
    try:
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, "scanner.zip")
        
        # Download the zip file
        urllib.request.urlretrieve(repo_url, zip_path)
        print_success("Downloaded scanner files")
        
        # Extract to current directory
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(".")
        
        # Find the extracted directory
        extracted_dirs = [d for d in os.listdir(".") if d.startswith("Stonerish-")]
        if extracted_dirs:
            extracted_dir = extracted_dirs[0]
            
            # Move files to current directory
            for item in os.listdir(extracted_dir):
                src = os.path.join(extracted_dir, item)
                dst = item
                if os.path.isdir(src):
                    if os.path.exists(dst):
                        import shutil
                        shutil.rmtree(dst)
                    os.rename(src, dst)
                else:
                    if os.path.exists(dst):
                        os.remove(dst)
                    os.rename(src, dst)
            
            # Remove the extracted directory
            os.rmdir(extracted_dir)
            
        print_success("Extracted scanner files")
        return True
        
    except Exception as e:
        print_error(f"Failed to download scanner: {e}")
        return False

def create_launcher():
    """Create launcher scripts"""
    print_status("Creating launcher scripts...")
    
    # Windows launcher
    if sys.platform == "win32":
        with open("launch_scanner.bat", "w") as f:
            f.write("""@echo off
echo Starting Enhanced Payment & Credential Scanner...
python enhanced_scanner.py
pause
""")
        print_success("Created launch_scanner.bat")
    
    # Unix launcher
    else:
        with open("launch_scanner.sh", "w") as f:
            f.write("""#!/bin/bash
echo "Starting Enhanced Payment & Credential Scanner..."
python3 enhanced_scanner.py
""")
        os.chmod("launch_scanner.sh", 0o755)
        print_success("Created launch_scanner.sh")

def run_tests():
    """Run installation tests if available"""
    if os.path.exists("test_installation.py"):
        print_status("Running installation tests...")
        try:
            result = subprocess.run([sys.executable, "test_installation.py"], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                print_success("All tests passed!")
            else:
                print_error("Some tests failed")
                print(result.stdout)
        except Exception as e:
            print_error(f"Could not run tests: {e}")

def main():
    """Main installation function"""
    print("🚀 Enhanced Payment & Credential Scanner - One-Click Installer")
    print("=" * 65)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install packages
    install_pip_packages()
    
    # Download scanner if not already present
    if not os.path.exists("enhanced_scanner.py"):
        if not download_scanner():
            print_error("Installation failed - could not download scanner")
            return False
    else:
        print_success("Scanner files already present")
    
    # Create launchers
    create_launcher()
    
    # Run tests
    run_tests()
    
    print("\n" + "=" * 65)
    print_success("🎉 Installation completed successfully!")
    print("\n📋 How to run:")
    
    if sys.platform == "win32":
        print("   • Double-click: launch_scanner.bat")
        print("   • Or run: python enhanced_scanner.py")
        print("\n⚠️  For network capture: Run as Administrator")
    else:
        print("   • Run: ./launch_scanner.sh")
        print("   • Or run: python3 enhanced_scanner.py")
        print("\n⚠️  For network capture: Run with sudo")
    
    print("\n📚 Documentation:")
    print("   • README.md - Full documentation")
    print("   • QUICK_START.md - Quick start guide")
    print("   • test_installation.py - Test your setup")
    
    print("\n🔍 Happy scanning!")
    return True

if __name__ == "__main__":
    try:
        success = main()
        if not success:
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n❌ Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Installation failed: {e}")
        sys.exit(1)
