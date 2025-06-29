#!/usr/bin/env python3
"""
Installation Test Script
Validates that all components are properly installed and functional
"""

import sys
import os

def test_imports():
    """Test all required imports"""
    print("Testing imports...")
    
    try:
        import PyQt6
        print("✅ PyQt6 imported successfully")
    except ImportError as e:
        print(f"❌ PyQt6 import failed: {e}")
        return False
    
    try:
        from PyQt6.QtWidgets import QApplication
        print("✅ PyQt6.QtWidgets imported successfully")
    except ImportError as e:
        print(f"❌ PyQt6.QtWidgets import failed: {e}")
        return False
    
    try:
        import scapy
        print("✅ Scapy imported successfully")
        network_available = True
    except ImportError as e:
        print(f"⚠️ Scapy import failed: {e}")
        print("   Network analysis features will be limited")
        network_available = False
    
    try:
        import yaml
        print("✅ PyYAML imported successfully")
    except ImportError as e:
        print(f"⚠️ PyYAML import failed: {e}")
        print("   YAML configuration parsing will be limited")
    
    try:
        import configparser
        print("✅ ConfigParser imported successfully")
    except ImportError as e:
        print(f"❌ ConfigParser import failed: {e}")
        return False
    
    return True

def test_modules():
    """Test custom modules"""
    print("\nTesting custom modules...")
    
    try:
        from network_analyzer import NetworkAnalyzer
        print("✅ NetworkAnalyzer imported successfully")
        
        analyzer = NetworkAnalyzer()
        print("✅ NetworkAnalyzer instantiated successfully")
        
        # Test basic functionality
        protocols = analyzer.supported_protocols
        print(f"✅ Supported protocols: {len(protocols)} protocols")
        
    except ImportError as e:
        print(f"❌ NetworkAnalyzer import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ NetworkAnalyzer test failed: {e}")
        return False
    
    try:
        from repository_scanner import RepositoryScanner
        print("✅ RepositoryScanner imported successfully")
        
        scanner = RepositoryScanner()
        print("✅ RepositoryScanner instantiated successfully")
        
        # Test basic functionality
        file_patterns = len(scanner.credential_files)
        print(f"✅ Credential file patterns: {file_patterns} patterns")
        
    except ImportError as e:
        print(f"❌ RepositoryScanner import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ RepositoryScanner test failed: {e}")
        return False
    
    return True

def test_gui():
    """Test GUI components"""
    print("\nTesting GUI components...")
    
    try:
        from enhanced_scanner import EnhancedScannerApp
        print("✅ EnhancedScannerApp imported successfully")
        
        # Test QApplication creation (without showing GUI)
        app = QApplication([])
        print("✅ QApplication created successfully")
        
        # Test main window creation
        window = EnhancedScannerApp()
        print("✅ EnhancedScannerApp instantiated successfully")
        
        # Test basic properties
        title = window.windowTitle()
        print(f"✅ Window title: {title}")
        
        app.quit()
        return True
        
    except ImportError as e:
        print(f"❌ EnhancedScannerApp import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ GUI test failed: {e}")
        return False

def test_file_access():
    """Test file access and permissions"""
    print("\nTesting file access...")
    
    # Test current directory access
    try:
        files = os.listdir('.')
        print(f"✅ Current directory accessible ({len(files)} items)")
    except Exception as e:
        print(f"❌ Current directory access failed: {e}")
        return False
    
    # Test write permissions
    try:
        test_file = 'test_write_permission.tmp'
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
        print("✅ Write permissions available")
    except Exception as e:
        print(f"❌ Write permission test failed: {e}")
        return False
    
    return True

def test_network_capabilities():
    """Test network analysis capabilities"""
    print("\nTesting network capabilities...")
    
    try:
        from network_analyzer import NetworkAnalyzer
        analyzer = NetworkAnalyzer()
        
        # Test interface enumeration
        interfaces = analyzer.get_network_interfaces()
        if interfaces:
            print(f"✅ Network interfaces detected: {len(interfaces)} interfaces")
            print(f"   Available interfaces: {', '.join(interfaces[:3])}{'...' if len(interfaces) > 3 else ''}")
        else:
            print("⚠️ No network interfaces detected")
            print("   Live capture may not be available")
        
        return True
        
    except Exception as e:
        print(f"⚠️ Network capability test failed: {e}")
        print("   Network features may be limited")
        return True  # Non-critical failure

def main():
    """Run all tests"""
    print("Enhanced Payment & Credential Scanner - Installation Test")
    print("=" * 60)
    
    tests = [
        ("Import Test", test_imports),
        ("Module Test", test_modules),
        ("GUI Test", test_gui),
        ("File Access Test", test_file_access),
        ("Network Capabilities Test", test_network_capabilities)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * 30)
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The application is ready to use.")
        print("\nTo start the application, run:")
        print("   python enhanced_scanner.py")
    else:
        print("⚠️ Some tests failed. Please check the error messages above.")
        print("\nCommon solutions:")
        print("- Install missing dependencies: pip install -r requirements.txt")
        print("- Run with administrator privileges for network features")
        print("- Check Python version (3.7+ required)")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
