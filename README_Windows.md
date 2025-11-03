# ML Intrusion Detection System - Windows Integration

Complete setup guide for running the ML-based Intrusion Detection System on Windows laptops with real-time network monitoring.

## Quick Start

### Option 1: Automated Setup (Recommended)
```bash
# Run the automated installer
python python/setup_windows.py
```

### Option 2: Manual Setup
```bash
# Install dependencies
pip install -r python/requirements_windows.txt

# Start the system
python python/api_server.py
```

## Prerequisites

### Required Software
1. **Python 3.7+** - [Download from python.org](https://python.org)
2. **Node.js 16+** - [Download from nodejs.org](https://nodejs.org)

### Optional (for Real Packet Capture)
1. **Npcap** - [Download from npcap.com](https://npcap.com/#download)
   - Required for real network packet capture
   - System works in simulation mode without it

2. **Administrator Privileges**
   - Required for raw packet capture
   - Right-click Command Prompt → "Run as Administrator"

## Installation Steps

### 1. Clone and Setup
```bash
# Navigate to project directory
cd ml-intrusion-detection-system

# Install Python dependencies
pip install -r python/requirements_windows.txt

# Install Node.js dependencies
npm install
```

### 2. Configure Windows Firewall (Optional)
```bash
# Allow Python through Windows Firewall
netsh advfirewall firewall add rule name="Python IDS" dir=in action=allow program="python.exe"
```

### 3. Install Npcap (Optional)
1. Download Npcap from https://npcap.com/#download
2. Run installer as Administrator
3. Select "Install Npcap in WinPcap API-compatible Mode"

## Running the System

### Start Backend (Python API)
```bash
# Option 1: With Administrator privileges (full features)
# Right-click Command Prompt → "Run as Administrator"
cd python
python api_server.py

# Option 2: Normal user (simulation mode)
python python/api_server.py
```

### Start Frontend (React Web Interface)
```bash
# In a new terminal
npm run dev
```

### Access the System
Open your browser to: `http://localhost:5173`

## Features Available on Windows

### ✅ Full Real-time Monitoring (with Admin + Npcap)
- Live packet capture from network interfaces
- Real protocol analysis (TCP, UDP, HTTP, HTTPS, DNS)
- Actual threat detection using ML algorithms
- Live traffic statistics and flow analysis

### ✅ Simulation Mode (without Admin/Npcap)
- Simulated network traffic for demonstration
- Full ML training and inference capabilities
- Complete web interface functionality
- Export and analysis features

### ✅ Cross-platform Compatibility
- Automatic detection of Windows environment
- Fallback to simulation when privileges unavailable
- Same interface works on Windows, Linux, and macOS

## Network Interfaces

The system automatically detects available network interfaces:

```python
# View available interfaces
python -c "from python.windows_monitor import WindowsNetworkMonitor; print(WindowsNetworkMonitor().get_network_interfaces())"
```

Common Windows interfaces:
- **Ethernet**: Physical network connection
- **Wi-Fi**: Wireless network connection
- **Loopback**: Local system traffic (127.0.0.1)

## Troubleshooting

### "Permission Denied" Error
**Solution**: Run Command Prompt as Administrator
```bash
# Right-click Command Prompt → "Run as Administrator"
python python/api_server.py
```

### "Scapy not found" Error
**Solution**: Install Scapy
```bash
pip install scapy
```

### "No packets captured" Issue
**Solutions**:
1. Install Npcap: https://npcap.com/#download
2. Run as Administrator
3. Check Windows Firewall settings
4. Use simulation mode (system works without real capture)

### Firewall Blocking Connections
**Solution**: Add firewall exception
```bash
netsh advfirewall firewall add rule name="Python IDS" dir=in action=allow program="python.exe"
```

## Performance Optimization

### For High-Traffic Networks
```python
# Modify buffer size in config
{
  "packet_capture": {
    "buffer_size": 5000,  # Increase for high traffic
    "sampling_rate": 0.1  # Sample 10% of packets
  }
}
```

### For Low-Resource Systems
```python
# Reduce ML model complexity
{
  "ml": {
    "model_type": "lightweight",
    "training_samples": 500
  }
}
```

## Security Considerations

### Network Access
- Raw packet capture requires Administrator privileges
- System can access all network traffic on the machine
- Use in controlled environments only

### Data Privacy
- Packet data is processed locally
- No data sent to external servers
- Export functions save data locally only

### Production Deployment
- Run on dedicated security workstation
- Configure proper access controls
- Monitor system resource usage
- Regular security updates

## Integration Examples

### With Windows Security Tools
```python
# Integration with Windows Event Log
import win32evtlog
import win32evtlogutil

# Log threats to Windows Event Log
def log_threat_to_windows(threat):
    win32evtlogutil.ReportEvent(
        "ML-IDS",
        1001,
        eventType=win32evtlog.EVENTLOG_WARNING_TYPE,
        strings=[f"Threat detected: {threat['type']}"]
    )
```

### With PowerShell
```powershell
# PowerShell script to start IDS
Start-Process python -ArgumentList "python/api_server.py" -Verb RunAs
Start-Process npm -ArgumentList "run dev"
```

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11
- **RAM**: 4GB
- **CPU**: Dual-core 2GHz
- **Storage**: 1GB free space
- **Network**: Any network interface

### Recommended Requirements
- **OS**: Windows 10/11 Pro
- **RAM**: 8GB+
- **CPU**: Quad-core 3GHz+
- **Storage**: 5GB+ free space
- **Network**: Gigabit Ethernet
- **Privileges**: Administrator access

## Support

For Windows-specific issues:
1. Check Windows Event Viewer for system errors
2. Verify Python and Node.js installations
3. Ensure network interfaces are active
4. Test with simulation mode first
5. Check antivirus software interference

The system is designed to work seamlessly on Windows laptops with automatic fallback to simulation mode when real packet capture is not available.