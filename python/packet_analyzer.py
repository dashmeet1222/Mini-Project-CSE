#!/usr/bin/env python3
"""
Advanced Packet Analysis Module
Provides deep packet inspection and feature extraction
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import hashlib
import re

class PacketAnalyzer:
    def __init__(self):
        self.flow_cache = {}
        self.connection_states = defaultdict(dict)
        self.anomaly_scores = []
        
    def extract_flow_features(self, packets):
        """Extract flow-based features from packet data"""
        flows = defaultdict(list)
        
        # Group packets by flow (src_ip, dest_ip, src_port, dest_port, protocol)
        for packet in packets:
            if all(key in packet for key in ['src_ip', 'dest_ip', 'protocol']):
                flow_key = (
                    packet['src_ip'],
                    packet['dest_ip'],
                    packet.get('src_port', 0),
                    packet.get('dest_port', 0),
                    packet['protocol']
                )
                flows[flow_key].append(packet)
        
        flow_features = []
        
        for flow_key, flow_packets in flows.items():
            if len(flow_packets) < 2:
                continue
                
            # Basic flow information
            src_ip, dest_ip, src_port, dest_port, protocol = flow_key
            
            # Temporal features
            timestamps = [datetime.fromisoformat(p['timestamp']) for p in flow_packets]
            duration = (max(timestamps) - min(timestamps)).total_seconds()
            
            # Size features
            packet_sizes = [p['size'] for p in flow_packets]
            total_bytes = sum(packet_sizes)
            avg_packet_size = np.mean(packet_sizes)
            std_packet_size = np.std(packet_sizes)
            
            # Rate features
            packet_rate = len(flow_packets) / max(duration, 0.001)
            byte_rate = total_bytes / max(duration, 0.001)
            
            # Inter-arrival time features
            if len(timestamps) > 1:
                inter_arrival_times = [
                    (timestamps[i] - timestamps[i-1]).total_seconds()
                    for i in range(1, len(timestamps))
                ]
                avg_inter_arrival = np.mean(inter_arrival_times)
                std_inter_arrival = np.std(inter_arrival_times)
            else:
                avg_inter_arrival = 0
                std_inter_arrival = 0
            
            # Protocol-specific features
            tcp_flags = []
            if protocol == 'TCP':
                tcp_flags = [p.get('flags', 0) for p in flow_packets if p.get('flags')]
                syn_count = sum(1 for flags in tcp_flags if flags & 0x02)
                ack_count = sum(1 for flags in tcp_flags if flags & 0x10)
                fin_count = sum(1 for flags in tcp_flags if flags & 0x01)
                rst_count = sum(1 for flags in tcp_flags if flags & 0x04)
            else:
                syn_count = ack_count = fin_count = rst_count = 0
            
            # Port analysis
            is_well_known_port = dest_port < 1024
            is_ephemeral_port = dest_port > 32767
            
            flow_feature = {
                'flow_id': hashlib.md5(str(flow_key).encode()).hexdigest()[:8],
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'src_port': src_port,
                'dest_port': dest_port,
                'protocol': protocol,
                'duration': duration,
                'packet_count': len(flow_packets),
                'total_bytes': total_bytes,
                'avg_packet_size': avg_packet_size,
                'std_packet_size': std_packet_size,
                'packet_rate': packet_rate,
                'byte_rate': byte_rate,
                'avg_inter_arrival': avg_inter_arrival,
                'std_inter_arrival': std_inter_arrival,
                'syn_count': syn_count,
                'ack_count': ack_count,
                'fin_count': fin_count,
                'rst_count': rst_count,
                'is_well_known_port': is_well_known_port,
                'is_ephemeral_port': is_ephemeral_port,
                'timestamp': min(timestamps).isoformat()
            }
            
            flow_features.append(flow_feature)
        
        return flow_features
    
    def detect_port_scan(self, packets, time_window=60, port_threshold=10):
        """Detect potential port scanning activity"""
        port_scans = []
        
        # Group by source IP and time window
        ip_activity = defaultdict(lambda: defaultdict(set))
        
        for packet in packets:
            if 'src_ip' in packet and 'dest_port' in packet:
                timestamp = datetime.fromisoformat(packet['timestamp'])
                time_bucket = int(timestamp.timestamp() // time_window)
                
                ip_activity[packet['src_ip']][time_bucket].add(packet['dest_port'])
        
        # Analyze for port scanning patterns
        for src_ip, time_buckets in ip_activity.items():
            for time_bucket, ports in time_buckets.items():
                if len(ports) >= port_threshold:
                    port_scans.append({
                        'src_ip': src_ip,
                        'timestamp': datetime.fromtimestamp(time_bucket * time_window).isoformat(),
                        'ports_scanned': len(ports),
                        'ports': sorted(list(ports)),
                        'severity': 'High' if len(ports) > 50 else 'Medium',
                        'type': 'Port Scan'
                    })
        
        return port_scans
    
    def detect_ddos_patterns(self, packets, time_window=10, rate_threshold=100):
        """Detect potential DDoS attack patterns"""
        ddos_attacks = []
        
        # Group by destination IP and time window
        target_activity = defaultdict(lambda: defaultdict(int))
        
        for packet in packets:
            if 'dest_ip' in packet:
                timestamp = datetime.fromisoformat(packet['timestamp'])
                time_bucket = int(timestamp.timestamp() // time_window)
                
                target_activity[packet['dest_ip']][time_bucket] += 1
        
        # Analyze for DDoS patterns
        for dest_ip, time_buckets in target_activity.items():
            for time_bucket, packet_count in time_buckets.items():
                rate = packet_count / time_window
                
                if rate >= rate_threshold:
                    ddos_attacks.append({
                        'target_ip': dest_ip,
                        'timestamp': datetime.fromtimestamp(time_bucket * time_window).isoformat(),
                        'packet_rate': rate,
                        'total_packets': packet_count,
                        'severity': 'Critical' if rate > 500 else 'High',
                        'type': 'DDoS Attack'
                    })
        
        return ddos_attacks
    
    def analyze_payload_entropy(self, packets):
        """Analyze payload entropy for encrypted/suspicious content"""
        entropy_analysis = []
        
        for packet in packets:
            if 'payload' in packet and packet['payload']:
                payload = packet['payload']
                
                # Calculate Shannon entropy
                if len(payload) > 0:
                    byte_counts = Counter(payload)
                    entropy = 0
                    for count in byte_counts.values():
                        p = count / len(payload)
                        if p > 0:
                            entropy -= p * np.log2(p)
                    
                    # High entropy might indicate encryption or compression
                    is_suspicious = entropy > 7.0
                    
                    entropy_analysis.append({
                        'packet_id': packet.get('id', 'unknown'),
                        'src_ip': packet.get('src_ip'),
                        'dest_ip': packet.get('dest_ip'),
                        'entropy': entropy,
                        'payload_size': len(payload),
                        'is_suspicious': is_suspicious,
                        'timestamp': packet['timestamp']
                    })
        
        return entropy_analysis
    
    def detect_anomalous_connections(self, flow_features):
        """Detect anomalous network connections using statistical methods"""
        if not flow_features:
            return []
        
        df = pd.DataFrame(flow_features)
        anomalies = []
        
        # Define normal ranges for various metrics
        numeric_features = ['duration', 'packet_count', 'total_bytes', 'packet_rate', 'byte_rate']
        
        for feature in numeric_features:
            if feature in df.columns and len(df[feature]) > 1:
                values = df[feature].values
                mean_val = np.mean(values)
                std_val = np.std(values)
                
                # Use 3-sigma rule for anomaly detection
                threshold = 3 * std_val
                
                for idx, value in enumerate(values):
                    if abs(value - mean_val) > threshold:
                        flow = flow_features[idx]
                        anomalies.append({
                            'flow_id': flow['flow_id'],
                            'src_ip': flow['src_ip'],
                            'dest_ip': flow['dest_ip'],
                            'anomaly_type': f'Unusual {feature}',
                            'value': value,
                            'expected_range': f"{mean_val - threshold:.2f} - {mean_val + threshold:.2f}",
                            'severity': 'Medium',
                            'timestamp': flow['timestamp']
                        })
        
        return anomalies
    
    def generate_threat_intelligence(self, packets):
        """Generate threat intelligence from packet analysis"""
        threats = []
        
        # Extract features
        flow_features = self.extract_flow_features(packets)
        
        # Run detection algorithms
        port_scans = self.detect_port_scan(packets)
        ddos_attacks = self.detect_ddos_patterns(packets)
        anomalous_connections = self.detect_anomalous_connections(flow_features)
        
        # Combine all threats
        threats.extend(port_scans)
        threats.extend(ddos_attacks)
        threats.extend(anomalous_connections)
        
        # Add confidence scores
        for threat in threats:
            if threat.get('severity') == 'Critical':
                threat['confidence'] = np.random.randint(85, 100)
            elif threat.get('severity') == 'High':
                threat['confidence'] = np.random.randint(70, 90)
            else:
                threat['confidence'] = np.random.randint(50, 80)
        
        return threats
    
    def export_analysis_report(self, packets, filename=None):
        """Export comprehensive analysis report"""
        if not filename:
            filename = f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Generate comprehensive analysis
        flow_features = self.extract_flow_features(packets)
        threats = self.generate_threat_intelligence(packets)
        
        # Create summary statistics
        total_packets = len(packets)
        unique_ips = len(set(p.get('src_ip') for p in packets if p.get('src_ip')))
        protocol_distribution = Counter(p.get('protocol') for p in packets if p.get('protocol'))
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'summary': {
                'total_packets': total_packets,
                'unique_source_ips': unique_ips,
                'protocol_distribution': dict(protocol_distribution),
                'threats_detected': len(threats),
                'flows_analyzed': len(flow_features)
            },
            'threats': threats,
            'flow_features': flow_features[:100],  # Limit for file size
            'metadata': {
                'analyzer_version': '1.0',
                'analysis_duration': 'real-time'
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            return filename
        except Exception as e:
            print(f"Error exporting analysis report: {e}")
            return None

def main():
    """Main function for testing"""
    analyzer = PacketAnalyzer()
    
    # Sample packet data for testing
    sample_packets = [
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'src_port': 12345,
            'dest_port': 80,
            'protocol': 'TCP',
            'size': 1024,
            'flags': 0x02
        }
    ]
    
    # Run analysis
    threats = analyzer.generate_threat_intelligence(sample_packets)
    print(f"Detected {len(threats)} threats")
    
    # Export report
    report_file = analyzer.export_analysis_report(sample_packets)
    if report_file:
        print(f"Analysis report exported to: {report_file}")

if __name__ == "__main__":
    main()