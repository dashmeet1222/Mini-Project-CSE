#!/usr/bin/env python3
"""
Network Flow Analyzer for NIDS
Advanced network flow analysis, correlation, and behavioral analysis
"""

import json
import time
import hashlib
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Any

class NetworkFlowAnalyzer:
    def __init__(self):
        self.active_flows = {}
        self.completed_flows = []
        self.flow_statistics = defaultdict(int)
        self.network_baselines = {}
        self.suspicious_patterns = []
        
    def create_flow_key(self, packet: Dict) -> str:
        """Create unique flow identifier from packet 5-tuple"""
        src_ip = packet.get('src_ip', '')
        dest_ip = packet.get('dest_ip', '')
        src_port = packet.get('src_port', 0)
        dest_port = packet.get('dest_port', 0)
        protocol = packet.get('protocol', '')
        
        # Create bidirectional flow key (normalize direction)
        if src_ip < dest_ip or (src_ip == dest_ip and src_port < dest_port):
            flow_tuple = (src_ip, dest_ip, src_port, dest_port, protocol)
        else:
            flow_tuple = (dest_ip, src_ip, dest_port, src_port, protocol)
            
        return hashlib.md5(str(flow_tuple).encode()).hexdigest()[:16]
    
    def analyze_network_flows(self, packets: List[Dict]) -> List[Dict]:
        """Analyze network packets and extract flow-based features"""
        flows = defaultdict(list)
        
        # Group packets by flow
        for packet in packets:
            flow_key = self.create_flow_key(packet)
            flows[flow_key].append(packet)
        
        flow_features = []
        
        for flow_key, flow_packets in flows.items():
            if len(flow_packets) < 2:
                continue
                
            features = self.extract_flow_features(flow_key, flow_packets)
            if features:
                flow_features.append(features)
                
        return flow_features
    
    def extract_flow_features(self, flow_key: str, packets: List[Dict]) -> Dict:
        """Extract comprehensive features from network flow"""
        if not packets:
            return None
            
        # Sort packets by timestamp
        packets.sort(key=lambda x: x.get('timestamp', ''))
        
        # Basic flow information
        first_packet = packets[0]
        last_packet = packets[-1]
        
        src_ip = first_packet.get('src_ip', '')
        dest_ip = first_packet.get('dest_ip', '')
        src_port = first_packet.get('src_port', 0)
        dest_port = first_packet.get('dest_port', 0)
        protocol = first_packet.get('protocol', '')
        
        # Temporal features
        start_time = datetime.fromisoformat(first_packet['timestamp'])
        end_time = datetime.fromisoformat(last_packet['timestamp'])
        duration = (end_time - start_time).total_seconds()
        
        # Size and count features
        packet_sizes = [p.get('size', 0) for p in packets]
        total_bytes = sum(packet_sizes)
        packet_count = len(packets)
        
        # Rate features
        packet_rate = packet_count / max(duration, 0.001)
        byte_rate = total_bytes / max(duration, 0.001)
        
        # Statistical features
        avg_packet_size = np.mean(packet_sizes) if packet_sizes else 0
        std_packet_size = np.std(packet_sizes) if len(packet_sizes) > 1 else 0
        
        # Inter-arrival time analysis
        inter_arrival_times = []
        if len(packets) > 1:
            for i in range(1, len(packets)):
                prev_time = datetime.fromisoformat(packets[i-1]['timestamp'])
                curr_time = datetime.fromisoformat(packets[i]['timestamp'])
                inter_arrival_times.append((curr_time - prev_time).total_seconds())
        
        avg_inter_arrival = np.mean(inter_arrival_times) if inter_arrival_times else 0
        std_inter_arrival = np.std(inter_arrival_times) if len(inter_arrival_times) > 1 else 0
        
        # Protocol-specific features
        tcp_flags = self.analyze_tcp_flags(packets)
        
        # Network behavior features
        network_features = self.extract_network_behavior_features(packets)
        
        # Port analysis
        port_features = self.analyze_port_behavior(src_port, dest_port)
        
        # Geolocation features (simplified)
        geo_features = self.analyze_geolocation(src_ip, dest_ip)
        
        flow_feature = {
            'flow_id': flow_key,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'src_port': src_port,
            'dest_port': dest_port,
            'protocol': protocol,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': duration,
            'packet_count': packet_count,
            'total_bytes': total_bytes,
            'avg_packet_size': avg_packet_size,
            'std_packet_size': std_packet_size,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'avg_inter_arrival': avg_inter_arrival,
            'std_inter_arrival': std_inter_arrival,
            **tcp_flags,
            **network_features,
            **port_features,
            **geo_features
        }
        
        return flow_feature
    
    def analyze_tcp_flags(self, packets: List[Dict]) -> Dict:
        """Analyze TCP flag patterns in flow"""
        flag_counts = {
            'syn_count': 0,
            'ack_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'urg_count': 0
        }
        
        for packet in packets:
            if packet.get('protocol') == 'TCP' and 'flags' in packet:
                flags = packet['flags']
                if flags & 0x02:  # SYN
                    flag_counts['syn_count'] += 1
                if flags & 0x10:  # ACK
                    flag_counts['ack_count'] += 1
                if flags & 0x01:  # FIN
                    flag_counts['fin_count'] += 1
                if flags & 0x04:  # RST
                    flag_counts['rst_count'] += 1
                if flags & 0x08:  # PSH
                    flag_counts['psh_count'] += 1
                if flags & 0x20:  # URG
                    flag_counts['urg_count'] += 1
        
        return flag_counts
    
    def extract_network_behavior_features(self, packets: List[Dict]) -> Dict:
        """Extract network behavior patterns"""
        # Payload entropy analysis
        payload_entropies = []
        for packet in packets:
            if 'payload' in packet and packet['payload']:
                entropy = self.calculate_entropy(packet['payload'])
                payload_entropies.append(entropy)
        
        avg_entropy = np.mean(payload_entropies) if payload_entropies else 0
        
        # Direction analysis
        forward_packets = 0
        backward_packets = 0
        first_src = packets[0].get('src_ip', '')
        
        for packet in packets:
            if packet.get('src_ip') == first_src:
                forward_packets += 1
            else:
                backward_packets += 1
        
        # Time-based patterns
        time_patterns = self.analyze_time_patterns(packets)
        
        return {
            'avg_payload_entropy': avg_entropy,
            'forward_packets': forward_packets,
            'backward_packets': backward_packets,
            'bidirectional_ratio': backward_packets / max(forward_packets, 1),
            **time_patterns
        }
    
    def analyze_port_behavior(self, src_port: int, dest_port: int) -> Dict:
        """Analyze port usage patterns"""
        well_known_ports = set(range(1, 1024))
        registered_ports = set(range(1024, 49152))
        ephemeral_ports = set(range(49152, 65536))
        
        return {
            'src_is_well_known': src_port in well_known_ports,
            'dest_is_well_known': dest_port in well_known_ports,
            'src_is_registered': src_port in registered_ports,
            'dest_is_registered': dest_port in registered_ports,
            'src_is_ephemeral': src_port in ephemeral_ports,
            'dest_is_ephemeral': dest_port in ephemeral_ports,
            'port_difference': abs(src_port - dest_port)
        }
    
    def analyze_geolocation(self, src_ip: str, dest_ip: str) -> Dict:
        """Analyze IP geolocation patterns (simplified)"""
        # Simplified geolocation analysis
        # In production, use GeoIP2 or similar service
        
        def is_private_ip(ip: str) -> bool:
            """Check if IP is in private range"""
            try:
                parts = ip.split('.')
                if len(parts) != 4:
                    return False
                    
                first = int(parts[0])
                second = int(parts[1])
                
                # Private IP ranges
                if first == 10:
                    return True
                elif first == 172 and 16 <= second <= 31:
                    return True
                elif first == 192 and second == 168:
                    return True
                    
                return False
            except:
                return False
        
        return {
            'src_is_private': is_private_ip(src_ip),
            'dest_is_private': is_private_ip(dest_ip),
            'is_internal_flow': is_private_ip(src_ip) and is_private_ip(dest_ip),
            'is_outbound_flow': is_private_ip(src_ip) and not is_private_ip(dest_ip),
            'is_inbound_flow': not is_private_ip(src_ip) and is_private_ip(dest_ip)
        }
    
    def analyze_time_patterns(self, packets: List[Dict]) -> Dict:
        """Analyze temporal patterns in network flow"""
        if len(packets) < 2:
            return {'time_regularity': 0, 'burst_ratio': 0}
        
        # Calculate time intervals
        intervals = []
        for i in range(1, len(packets)):
            prev_time = datetime.fromisoformat(packets[i-1]['timestamp'])
            curr_time = datetime.fromisoformat(packets[i]['timestamp'])
            interval = (curr_time - prev_time).total_seconds()
            intervals.append(interval)
        
        # Time regularity (coefficient of variation)
        if intervals and np.mean(intervals) > 0:
            time_regularity = np.std(intervals) / np.mean(intervals)
        else:
            time_regularity = 0
        
        # Burst detection
        short_intervals = [i for i in intervals if i < 0.1]  # < 100ms
        burst_ratio = len(short_intervals) / len(intervals) if intervals else 0
        
        return {
            'time_regularity': time_regularity,
            'burst_ratio': burst_ratio,
            'avg_interval': np.mean(intervals) if intervals else 0
        }
    
    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count byte frequencies
        byte_counts = Counter(data)
        data_len = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            p = count / data_len
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def detect_network_anomalies(self, flow_features: List[Dict]) -> List[Dict]:
        """Detect network anomalies in flows"""
        anomalies = []
        
        if not flow_features:
            return anomalies
        
        # Convert to DataFrame for analysis
        df = pd.DataFrame(flow_features)
        
        # Statistical anomaly detection
        numeric_features = [
            'duration', 'packet_count', 'total_bytes', 'packet_rate', 
            'byte_rate', 'avg_packet_size', 'avg_inter_arrival'
        ]
        
        for feature in numeric_features:
            if feature in df.columns and len(df[feature]) > 1:
                values = df[feature].values
                mean_val = np.mean(values)
                std_val = np.std(values)
                
                # 3-sigma rule
                threshold = 3 * std_val
                
                for idx, value in enumerate(values):
                    if abs(value - mean_val) > threshold and std_val > 0:
                        flow = flow_features[idx]
                        anomalies.append({
                            'flow_id': flow['flow_id'],
                            'src_ip': flow['src_ip'],
                            'dest_ip': flow['dest_ip'],
                            'anomaly_type': f'Statistical anomaly in {feature}',
                            'anomaly_value': value,
                            'expected_range': f"{mean_val - threshold:.2f} - {mean_val + threshold:.2f}",
                            'severity': 'Medium',
                            'confidence': min(95, int(abs(value - mean_val) / std_val * 20)),
                            'timestamp': flow['start_time']
                        })
        
        return anomalies
    
    def detect_lateral_movement(self, flow_features: List[Dict]) -> List[Dict]:
        """Detect lateral movement patterns"""
        lateral_movement = []
        
        # Group flows by source IP
        src_ip_flows = defaultdict(list)
        for flow in flow_features:
            src_ip_flows[flow['src_ip']].append(flow)
        
        # Analyze each source IP for lateral movement patterns
        for src_ip, flows in src_ip_flows.items():
            if len(flows) < 3:  # Need multiple connections
                continue
            
            # Check for multiple internal destinations
            internal_destinations = set()
            for flow in flows:
                if flow.get('dest_is_private', False):
                    internal_destinations.add(flow['dest_ip'])
            
            # Lateral movement indicators
            if len(internal_destinations) >= 3:  # Connected to 3+ internal hosts
                # Check time window (within 1 hour)
                flow_times = [datetime.fromisoformat(f['start_time']) for f in flows]
                time_span = (max(flow_times) - min(flow_times)).total_seconds()
                
                if time_span <= 3600:  # Within 1 hour
                    lateral_movement.append({
                        'src_ip': src_ip,
                        'threat_type': 'Lateral Movement',
                        'destinations': list(internal_destinations),
                        'connection_count': len(flows),
                        'time_span': time_span,
                        'severity': 'High',
                        'confidence': min(95, len(internal_destinations) * 20),
                        'timestamp': min(flow_times).isoformat()
                    })
        
        return lateral_movement
    
    def detect_data_exfiltration(self, flow_features: List[Dict]) -> List[Dict]:
        """Detect data exfiltration patterns"""
        exfiltration = []
        
        # Look for large outbound transfers
        for flow in flow_features:
            if (flow.get('is_outbound_flow', False) and 
                flow.get('total_bytes', 0) > 10 * 1024 * 1024):  # > 10MB
                
                # Additional indicators
                indicators = []
                confidence = 60
                
                # High entropy (encrypted data)
                if flow.get('avg_payload_entropy', 0) > 7.0:
                    indicators.append('High entropy payload')
                    confidence += 15
                
                # Unusual destination
                if not flow.get('dest_is_well_known', False):
                    indicators.append('Unusual destination port')
                    confidence += 10
                
                # Long duration transfer
                if flow.get('duration', 0) > 300:  # > 5 minutes
                    indicators.append('Long duration transfer')
                    confidence += 10
                
                if indicators:
                    exfiltration.append({
                        'flow_id': flow['flow_id'],
                        'src_ip': flow['src_ip'],
                        'dest_ip': flow['dest_ip'],
                        'threat_type': 'Data Exfiltration',
                        'total_bytes': flow['total_bytes'],
                        'duration': flow['duration'],
                        'indicators': indicators,
                        'severity': 'Critical',
                        'confidence': min(95, confidence),
                        'timestamp': flow['start_time']
                    })
        
        return exfiltration
    
    def generate_network_intelligence(self, flow_features: List[Dict]) -> Dict:
        """Generate comprehensive network threat intelligence"""
        intelligence = {
            'timestamp': datetime.now().isoformat(),
            'flows_analyzed': len(flow_features),
            'anomalies': self.detect_network_anomalies(flow_features),
            'lateral_movement': self.detect_lateral_movement(flow_features),
            'data_exfiltration': self.detect_data_exfiltration(flow_features),
            'network_statistics': self.calculate_network_statistics(flow_features)
        }
        
        return intelligence
    
    def calculate_network_statistics(self, flow_features: List[Dict]) -> Dict:
        """Calculate network-wide statistics"""
        if not flow_features:
            return {}
        
        df = pd.DataFrame(flow_features)
        
        stats = {
            'total_flows': len(flow_features),
            'unique_src_ips': df['src_ip'].nunique() if 'src_ip' in df else 0,
            'unique_dest_ips': df['dest_ip'].nunique() if 'dest_ip' in df else 0,
            'total_bytes': df['total_bytes'].sum() if 'total_bytes' in df else 0,
            'avg_flow_duration': df['duration'].mean() if 'duration' in df else 0,
            'protocol_distribution': df['protocol'].value_counts().to_dict() if 'protocol' in df else {},
            'internal_flows': len(df[df.get('is_internal_flow', False)]) if 'is_internal_flow' in df else 0,
            'outbound_flows': len(df[df.get('is_outbound_flow', False)]) if 'is_outbound_flow' in df else 0,
            'inbound_flows': len(df[df.get('is_inbound_flow', False)]) if 'is_inbound_flow' in df else 0
        }
        
        return stats

def main():
    """Test network flow analyzer"""
    analyzer = NetworkFlowAnalyzer()
    
    # Sample network packets
    sample_packets = [
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dest_ip': '8.8.8.8',
            'src_port': 12345,
            'dest_port': 443,
            'protocol': 'TCP',
            'size': 1024,
            'flags': 0x18  # PSH+ACK
        },
        {
            'timestamp': (datetime.now() + timedelta(seconds=1)).isoformat(),
            'src_ip': '8.8.8.8',
            'dest_ip': '192.168.1.100',
            'src_port': 443,
            'dest_port': 12345,
            'protocol': 'TCP',
            'size': 512,
            'flags': 0x18  # PSH+ACK
        }
    ]
    
    # Analyze flows
    flow_features = analyzer.analyze_network_flows(sample_packets)
    print(f"Analyzed {len(flow_features)} network flows")
    
    # Generate intelligence
    intelligence = analyzer.generate_network_intelligence(flow_features)
    print(f"Generated intelligence with {len(intelligence['anomalies'])} anomalies")

if __name__ == "__main__":
    main()