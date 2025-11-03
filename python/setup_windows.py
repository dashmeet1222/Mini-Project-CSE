#!/usr/bin/env python3
"""
Windows Setup Script for ML Intrusion Detection System
Automatically configures the system for Windows environment
"""

import os
import sys
import subprocess
import platform
import ctypes
import json
from pathlib import Path

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("ERROR: Python 3.7 or higher is required")
        print(f"Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"✓ Python {version.major}.{version.minor}.{version.micro} detected")
    return True

def install_dependencies():
    """Install required Python packages"""
    print("Installing Python dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements_windows.txt"])
        print("✓ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Failed to install dependencies: {e}")
        return False

def check_npcap():
    """Check if Npcap is installed"""
    npcap_paths = [
        "C:\\Program Files\\Npcap\\npcap.dll",
        "C:\\Windows\\System32\\Npcap\\npcap.dll",
        "C:\\Windows\\System32\\wpcap.dll"
    ]
    
    for path in npcap_paths:
        if os.path.exists(path):
            print("✓ Npcap/WinPcap found - packet capture available")
            return True
    
    print("⚠ Npcap not found")
    print("  For real packet capture, install Npcap from: https://npcap.com/#download")
    print("  System will work in simulation mode without Npcap")
    return False

def check_firewall():
    """Check Windows Firewall status"""
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                              capture_output=True, text=True, shell=True)
        if "ON" in result.stdout:
            print("⚠ Windows Firewall is enabled")
            print("  You may need to allow Python through the firewall")
            print("  Or run: netsh advfirewall firewall add rule name=\"Python IDS\" dir=in action=allow program=\"python.exe\"")
        else:
            print("✓ Windows Firewall allows connections")
    except Exception as e:
        print(f"Could not check firewall status: {e}")

def create_config():
    """Create configuration file for Windows"""
    config = {
        "platform": "windows",
        "packet_capture": {
            "method": "scapy",
            "interface": "auto",
            "buffer_size": 1000
        },
        "api": {
            "host": "0.0.0.0",
            "port": 5000,
            "debug": True
        },
        "ml": {
            "models_path": "models/",
            "training_data_size": 1000
        }
    }
    
    with open("config.json", "w") as f:
        json.dump(config, f, indent=2)
    
    print("✓ Configuration file created")

def setup_directories():
    """Create necessary directories"""
    directories = ["models", "logs", "exports", "data"]
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    print("✓ Directories created")

def main():
    """Main setup function"""
    print("ML Intrusion Detection System - Windows Setup")
    print("=" * 50)
    
    if platform.system() != "Windows":
        print("This setup script is for Windows only")
        return False
    
    # Check administrator privileges
    if is_admin():
        print("✓ Running with Administrator privileges")
    else:
        print("⚠ Not running as Administrator")
        print("  Some features may not work without admin privileges")
        print("  Consider running as Administrator for full functionality")
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Check packet capture capabilities
    check_npcap()
    
    # Check firewall
    check_firewall()
    
    # Create configuration
    create_config()
    
    # Setup directories
    setup_directories()
    
    print("\n" + "=" * 50)
    print("Setup completed successfully!")
    print("\nTo start the system:")
    print("1. python api_server.py")
    print("2. Open browser to: http://localhost:3000")
    print("\nFor real-time packet capture:")
    print("- Run as Administrator")
    print("- Install Npcap if not already installed")
    print("\nThe system will work in demo mode without these requirements.")
    
    return True

if __name__ == "__main__":
    success = main()
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)