# Network Monitoring Python Modules

This directory contains Python modules for real-time network monitoring and machine learning-based threat detection.

## Modules

### 1. network_monitor.py
Real-time network packet capture and analysis module.

**Features:**
- Raw socket packet capture
- Ethernet, IP, TCP, UDP header parsing
- Real-time traffic statistics
- Packet export to JSON

**Usage:**
```python
from network_monitor import NetworkMonitor

monitor = NetworkMonitor()
monitor.start_monitoring()
packets = monitor.get_recent_packets()
```

### 2. packet_analyzer.py
Advanced packet analysis and feature extraction module.

**Features:**
- Flow-based feature extraction
- Port scan detection
- DDoS pattern detection
- Payload entropy analysis
- Anomaly detection

**Usage:**
```python
from packet_analyzer import PacketAnalyzer

analyzer = PacketAnalyzer()
threats = analyzer.generate_threat_intelligence(packets)
```

### 3. ml_detector.py
Machine learning threat detection module.

**Features:**
- Random Forest classifier
- Isolation Forest anomaly detection
- One-Class SVM
- Model training and persistence
- Real-time threat prediction

**Usage:**
```python
from ml_detector import MLThreatDetector

detector = MLThreatDetector()
detector.train_models()
threats = detector.predict_threats(flow_data)
```

### 4. api_server.py
Flask API server providing REST endpoints for the web interface.

**Features:**
- RESTful API endpoints
- Real-time monitoring control
- ML model training and prediction
- Data export functionality
- CORS support for web integration

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Run the API server:
```bash
python api_server.py
```

## API Endpoints

- `GET /api/status` - System status
- `POST /api/monitoring/start` - Start network monitoring
- `POST /api/monitoring/stop` - Stop network monitoring
- `GET /api/packets` - Get recent packets
- `GET /api/threats` - Get detected threats
- `GET /api/statistics` - Get traffic statistics
- `POST /api/ml/train` - Train ML models
- `POST /api/ml/predict` - Predict threats
- `GET /api/ml/models` - Get model information

## Requirements

- Python 3.7+
- Root privileges for packet capture
- Network interface access

## Security Notes

- Raw socket access requires root privileges
- Use in controlled environments only
- Monitor system resources during operation
- Implement proper access controls in production

## Integration with Web Interface

The Python modules integrate with the React web interface through the Flask API server. The web interface can:

1. Start/stop network monitoring
2. View real-time packet data
3. Train ML models
4. View threat predictions
5. Export analysis reports

## Performance Considerations

- Packet capture is CPU intensive
- ML training requires sufficient memory
- Consider sampling for high-traffic networks
- Monitor disk space for packet storage