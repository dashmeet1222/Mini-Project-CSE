#!/usr/bin/env python3
"""
API Server for Network Monitoring System
Provides REST API endpoints for the web interface
"""

import json
import time
import threading
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS

import platform
if platform.system() == "Windows":
    from windows_monitor import WindowsNetworkMonitor as NetworkMonitor
else:
    from network_monitor import NetworkMonitor
    
from packet_analyzer import PacketAnalyzer
from ml_detector import MLThreatDetector

app = Flask(__name__)
CORS(app)  # Enable CORS for web interface

# Global instances
network_monitor = NetworkMonitor()
packet_analyzer = PacketAnalyzer()
ml_detector = MLThreatDetector()

# Global state
monitoring_active = False
latest_packets = []
latest_threats = []
system_stats = {
    'packets_processed': 0,
    'threats_detected': 0,
    'uptime': 0
}

def background_analysis():
    """Background thread for continuous packet analysis"""
    global latest_packets, latest_threats, system_stats
    
    start_time = time.time()
    
    while True:
        try:
            if monitoring_active:
                # Get recent packets
                packets = network_monitor.get_recent_packets(100)
                latest_packets = packets
                
                if packets:
                    # Analyze packets
                    flow_features = packet_analyzer.extract_flow_features(packets)
                    
                    # Generate threat intelligence
                    threats = packet_analyzer.generate_threat_intelligence(packets)
                    
                    # ML-based threat detection (if models are trained)
                    if ml_detector.is_trained and flow_features:
                        ml_threats = ml_detector.predict_threats(flow_features)
                        threats.extend(ml_threats)
                    
                    latest_threats = threats
                    
                    # Update stats
                    system_stats['packets_processed'] = len(packets)
                    system_stats['threats_detected'] = len(threats)
                
                system_stats['uptime'] = int(time.time() - start_time)
            
            time.sleep(5)  # Analysis interval
            
        except Exception as e:
            print(f"Error in background analysis: {e}")
            time.sleep(10)

# Start background analysis thread
analysis_thread = threading.Thread(target=background_analysis, daemon=True)
analysis_thread.start()

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get system status"""
    return jsonify({
        'monitoring_active': monitoring_active,
        'ml_models_trained': ml_detector.is_trained,
        'uptime': system_stats['uptime'],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring():
    """Start network monitoring"""
    global monitoring_active
    
    try:
        success = network_monitor.start_monitoring()
        if success:
            monitoring_active = True
            return jsonify({'status': 'success', 'message': 'Monitoring started'})
        else:
            return jsonify({'status': 'error', 'message': 'Failed to start monitoring'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring():
    """Stop network monitoring"""
    global monitoring_active
    
    try:
        network_monitor.stop_monitoring()
        monitoring_active = False
        return jsonify({'status': 'success', 'message': 'Monitoring stopped'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/packets', methods=['GET'])
def get_packets():
    """Get recent network packets"""
    count = request.args.get('count', 50, type=int)
    return jsonify({
        'packets': latest_packets[-count:],
        'total_count': len(latest_packets),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get detected threats"""
    return jsonify({
        'threats': latest_threats,
        'total_count': len(latest_threats),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get traffic statistics"""
    traffic_stats = network_monitor.get_traffic_stats()
    
    return jsonify({
        'traffic_stats': traffic_stats,
        'system_stats': system_stats,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/analysis/flows', methods=['GET'])
def get_flow_analysis():
    """Get flow-based analysis"""
    if not latest_packets:
        return jsonify({'flows': [], 'message': 'No packets available'})
    
    try:
        flow_features = packet_analyzer.extract_flow_features(latest_packets)
        return jsonify({
            'flows': flow_features,
            'total_count': len(flow_features),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml/train', methods=['POST'])
def train_ml_models():
    """Train ML models"""
    try:
        # Train with synthetic data or provided data
        training_data = request.get_json() if request.is_json else None
        
        success = ml_detector.train_models(training_data)
        
        if success:
            return jsonify({
                'status': 'success',
                'message': 'Models trained successfully',
                'model_info': ml_detector.get_model_info()
            })
        else:
            return jsonify({'status': 'error', 'message': 'Training failed'}), 500
            
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ml/predict', methods=['POST'])
def predict_threats():
    """Predict threats using ML models"""
    if not ml_detector.is_trained:
        return jsonify({'error': 'Models not trained'}), 400
    
    try:
        flow_data = request.get_json()
        if not flow_data:
            # Use latest flow features
            flow_data = packet_analyzer.extract_flow_features(latest_packets)
        
        predictions = ml_detector.predict_threats(flow_data)
        
        return jsonify({
            'predictions': predictions,
            'total_count': len(predictions),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ml/models', methods=['GET'])
def get_model_info():
    """Get ML model information"""
    return jsonify(ml_detector.get_model_info())

@app.route('/api/export/packets', methods=['GET'])
def export_packets():
    """Export packets to file"""
    try:
        filename = network_monitor.export_packets_json()
        if filename:
            return jsonify({
                'status': 'success',
                'filename': filename,
                'message': f'Packets exported to {filename}'
            })
        else:
            return jsonify({'status': 'error', 'message': 'Export failed'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/export/analysis', methods=['GET'])
def export_analysis():
    """Export analysis report"""
    try:
        filename = packet_analyzer.export_analysis_report(latest_packets)
        if filename:
            return jsonify({
                'status': 'success',
                'filename': filename,
                'message': f'Analysis report exported to {filename}'
            })
        else:
            return jsonify({'status': 'error', 'message': 'Export failed'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

if __name__ == '__main__':
    print("Starting Network Monitoring API Server...")
    print("Initializing pre-trained ML models...")
    
    # Models are automatically initialized in constructor
    if ml_detector.is_trained:
        print("✓ ML models ready for real-time threat detection")
    else:
        print("⚠ Warning: ML models not properly initialized")
    
    print("API Server ready!")
    print("Endpoints available:")
    print("  GET  /api/status - System status")
    print("  POST /api/monitoring/start - Start monitoring")
    print("  POST /api/monitoring/stop - Stop monitoring")
    print("  GET  /api/packets - Get recent packets")
    print("  GET  /api/threats - Get detected threats")
    print("  GET  /api/statistics - Get traffic statistics")
    print("  POST /api/ml/predict - Predict threats")
    print("  GET  /api/ml/models - Get model info")
    
    app.run(host='0.0.0.0', port=5000, debug=True)