#!/usr/bin/env python3
"""
Network Topology Mapper for NIDS
Discovers and maps network topology, tracks network changes
"""

import json
import time
import subprocess
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import Dict, List, Set, Tuple, Any

class NetworkTopologyMapper:
    def __init__(self):
        self.network_hosts = {}
        self.network_connections = defaultdict(set)
        self.network_subnets = set()
        self.network_services = defaultdict(dict)
        self.topology_history = deque(maxlen=100)
        self.last_scan_time = None
        
    def discover_network_topology(self, packets: List[Dict]) -> Dict:
        """Discover network topology from packet analysis"""
        topology = {
            'timestamp': datetime.now().isoformat(),
            'hosts': {},
            'connections': {},
            'subnets': [],
            'services': {},
            'statistics': {}
        }
        
        # Analyze packets for topology information
        host_info = self.analyze_hosts_from_packets(packets)
        connections = self.analyze_connections_from_packets(packets)
        subnets = self.discover_subnets(host_info.keys())
        services = self.discover_services_from_packets(packets)
        
        topology['hosts'] = host_info
        topology['connections'] = connections
        topology['subnets'] = subnets
        topology['services'] = services
        topology['statistics'] = self.calculate_topology_statistics(topology)
        
        # Store in history
        self.topology_history.append(topology)
        
        return topology
    
    def analyze_hosts_from_packets(self, packets: List[Dict]) -> Dict:
        """Analyze host information from network packets"""
        hosts = {}
        
        for packet in packets:
            src_ip = packet.get('src_ip')
            dest_ip = packet.get('dest_ip')
            
            # Analyze source host
            if src_ip and self.is_valid_ip(src_ip):
                if src_ip not in hosts:
                    hosts[src_ip] = self.initialize_host_info(src_ip)
                
                self.update_host_info(hosts[src_ip], packet, 'source')
            
            # Analyze destination host
            if dest_ip and self.is_valid_ip(dest_ip):
                if dest_ip not in hosts:
                    hosts[dest_ip] = self.initialize_host_info(dest_ip)
                
                self.update_host_info(hosts[dest_ip], packet, 'destination')
        
        return hosts
    
    def initialize_host_info(self, ip: str) -> Dict:
        """Initialize host information structure"""
        return {
            'ip_address': ip,
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'packet_count': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'protocols': set(),
            'ports_used': set(),
            'services': set(),
            'connections': set(),
            'is_internal': self.is_internal_ip(ip),
            'host_type': self.classify_host_type(ip),
            'activity_level': 'unknown',
            'reputation': 'unknown'
        }
    
    def update_host_info(self, host_info: Dict, packet: Dict, direction: str):
        """Update host information with packet data"""
        host_info['last_seen'] = datetime.now().isoformat()
        host_info['packet_count'] += 1
        
        packet_size = packet.get('size', 0)
        if direction == 'source':
            host_info['bytes_sent'] += packet_size
        else:
            host_info['bytes_received'] += packet_size
        
        # Update protocol information
        protocol = packet.get('protocol')
        if protocol:
            host_info['protocols'].add(protocol)
        
        # Update port information
        src_port = packet.get('src_port')
        dest_port = packet.get('dest_port')
        
        if direction == 'source' and src_port:
            host_info['ports_used'].add(src_port)
        elif direction == 'destination' and dest_port:
            host_info['ports_used'].add(dest_port)
            
            # Identify services
            service = self.identify_service_by_port(dest_port, protocol)
            if service:
                host_info['services'].add(service)
        
        # Update activity level
        host_info['activity_level'] = self.calculate_activity_level(host_info)
    
    def analyze_connections_from_packets(self, packets: List[Dict]) -> Dict:
        """Analyze network connections from packets"""
        connections = defaultdict(lambda: {
            'packet_count': 0,
            'bytes_transferred': 0,
            'protocols': set(),
            'first_seen': None,
            'last_seen': None,
            'connection_type': 'unknown'
        })
        
        for packet in packets:
            src_ip = packet.get('src_ip')
            dest_ip = packet.get('dest_ip')
            
            if src_ip and dest_ip and self.is_valid_ip(src_ip) and self.is_valid_ip(dest_ip):
                # Create bidirectional connection key
                conn_key = tuple(sorted([src_ip, dest_ip]))
                
                conn = connections[conn_key]
                conn['packet_count'] += 1
                conn['bytes_transferred'] += packet.get('size', 0)
                
                protocol = packet.get('protocol')
                if protocol:
                    conn['protocols'].add(protocol)
                
                timestamp = packet.get('timestamp')
                if timestamp:
                    if not conn['first_seen']:
                        conn['first_seen'] = timestamp
                    conn['last_seen'] = timestamp
                
                # Classify connection type
                conn['connection_type'] = self.classify_connection_type(src_ip, dest_ip)
        
        # Convert sets to lists for JSON serialization
        for conn in connections.values():
            conn['protocols'] = list(conn['protocols'])
        
        return dict(connections)
    
    def discover_subnets(self, ip_addresses: List[str]) -> List[Dict]:
        """Discover network subnets from IP addresses"""
        subnets = {}
        
        for ip in ip_addresses:
            if not self.is_valid_ip(ip):
                continue
                
            try:
                # Assume /24 subnet for simplicity
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                subnet_key = str(network.network_address) + "/24"
                
                if subnet_key not in subnets:
                    subnets[subnet_key] = {
                        'network': subnet_key,
                        'hosts': set(),
                        'is_internal': self.is_internal_ip(ip),
                        'subnet_type': self.classify_subnet_type(ip)
                    }
                
                subnets[subnet_key]['hosts'].add(ip)
                
            except Exception as e:
                continue
        
        # Convert to list format
        subnet_list = []
        for subnet_info in subnets.values():
            subnet_info['hosts'] = list(subnet_info['hosts'])
            subnet_info['host_count'] = len(subnet_info['hosts'])
            subnet_list.append(subnet_info)
        
        return subnet_list
    
    def discover_services_from_packets(self, packets: List[Dict]) -> Dict:
        """Discover network services from packet analysis"""
        services = defaultdict(lambda: {
            'port': 0,
            'protocol': '',
            'service_name': '',
            'hosts': set(),
            'packet_count': 0,
            'first_seen': None,
            'last_seen': None
        })
        
        for packet in packets:
            dest_port = packet.get('dest_port')
            protocol = packet.get('protocol')
            dest_ip = packet.get('dest_ip')
            
            if dest_port and protocol and dest_ip:
                service_name = self.identify_service_by_port(dest_port, protocol)
                if service_name:
                    service_key = f"{service_name}_{dest_port}_{protocol}"
                    
                    service = services[service_key]
                    service['port'] = dest_port
                    service['protocol'] = protocol
                    service['service_name'] = service_name
                    service['hosts'].add(dest_ip)
                    service['packet_count'] += 1
                    
                    timestamp = packet.get('timestamp')
                    if timestamp:
                        if not service['first_seen']:
                            service['first_seen'] = timestamp
                        service['last_seen'] = timestamp
        
        # Convert sets to lists
        for service in services.values():
            service['hosts'] = list(service['hosts'])
            service['host_count'] = len(service['hosts'])
        
        return dict(services)
    
    def is_valid_ip(self, ip: str) -> bool:
        """Check if IP address is valid"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except:
            return False
    
    def is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is internal/private"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except:
            return False
    
    def classify_host_type(self, ip: str) -> str:
        """Classify host type based on IP address"""
        if not self.is_valid_ip(ip):
            return 'unknown'
        
        if self.is_internal_ip(ip):
            # Simple classification based on IP range
            parts = ip.split('.')
            if len(parts) == 4:
                try:
                    third_octet = int(parts[2])
                    if third_octet == 1:
                        return 'server'
                    elif third_octet == 10:
                        return 'dmz'
                    else:
                        return 'workstation'
                except:
                    return 'internal'
            return 'internal'
        else:
            return 'external'
    
    def classify_connection_type(self, src_ip: str, dest_ip: str) -> str:
        """Classify connection type"""
        src_internal = self.is_internal_ip(src_ip)
        dest_internal = self.is_internal_ip(dest_ip)
        
        if src_internal and dest_internal:
            return 'internal'
        elif src_internal and not dest_internal:
            return 'outbound'
        elif not src_internal and dest_internal:
            return 'inbound'
        else:
            return 'external'
    
    def classify_subnet_type(self, ip: str) -> str:
        """Classify subnet type"""
        if not self.is_internal_ip(ip):
            return 'external'
        
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                second_octet = int(parts[1])
                third_octet = int(parts[2])
                
                if parts[0] == '10':
                    if third_octet == 1:
                        return 'server_subnet'
                    elif third_octet == 10:
                        return 'dmz_subnet'
                    else:
                        return 'user_subnet'
                elif parts[0] == '192' and second_octet == 168:
                    return 'user_subnet'
                elif parts[0] == '172':
                    return 'corporate_subnet'
            except:
                pass
        
        return 'internal_subnet'
    
    def identify_service_by_port(self, port: int, protocol: str) -> str:
        """Identify service by port and protocol"""
        well_known_services = {
            (80, 'TCP'): 'HTTP',
            (443, 'TCP'): 'HTTPS',
            (22, 'TCP'): 'SSH',
            (21, 'TCP'): 'FTP',
            (25, 'TCP'): 'SMTP',
            (53, 'UDP'): 'DNS',
            (53, 'TCP'): 'DNS',
            (110, 'TCP'): 'POP3',
            (143, 'TCP'): 'IMAP',
            (993, 'TCP'): 'IMAPS',
            (995, 'TCP'): 'POP3S',
            (3389, 'TCP'): 'RDP',
            (1433, 'TCP'): 'MSSQL',
            (3306, 'TCP'): 'MySQL',
            (5432, 'TCP'): 'PostgreSQL',
            (6379, 'TCP'): 'Redis',
            (27017, 'TCP'): 'MongoDB'
        }
        
        return well_known_services.get((port, protocol.upper()), None)
    
    def calculate_activity_level(self, host_info: Dict) -> str:
        """Calculate host activity level"""
        packet_count = host_info.get('packet_count', 0)
        
        if packet_count > 1000:
            return 'high'
        elif packet_count > 100:
            return 'medium'
        elif packet_count > 10:
            return 'low'
        else:
            return 'minimal'
    
    def calculate_topology_statistics(self, topology: Dict) -> Dict:
        """Calculate topology statistics"""
        hosts = topology.get('hosts', {})
        connections = topology.get('connections', {})
        subnets = topology.get('subnets', [])
        services = topology.get('services', {})
        
        internal_hosts = sum(1 for h in hosts.values() if h.get('is_internal', False))
        external_hosts = len(hosts) - internal_hosts
        
        total_packets = sum(h.get('packet_count', 0) for h in hosts.values())
        total_bytes = sum(h.get('bytes_sent', 0) + h.get('bytes_received', 0) for h in hosts.values())
        
        return {
            'total_hosts': len(hosts),
            'internal_hosts': internal_hosts,
            'external_hosts': external_hosts,
            'total_connections': len(connections),
            'total_subnets': len(subnets),
            'total_services': len(services),
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'avg_packets_per_host': total_packets / max(len(hosts), 1),
            'avg_bytes_per_host': total_bytes / max(len(hosts), 1)
        }
    
    def detect_topology_changes(self) -> List[Dict]:
        """Detect changes in network topology"""
        changes = []
        
        if len(self.topology_history) < 2:
            return changes
        
        current = self.topology_history[-1]
        previous = self.topology_history[-2]
        
        # Detect new hosts
        current_hosts = set(current['hosts'].keys())
        previous_hosts = set(previous['hosts'].keys())
        
        new_hosts = current_hosts - previous_hosts
        removed_hosts = previous_hosts - current_hosts
        
        for host in new_hosts:
            changes.append({
                'type': 'new_host',
                'host': host,
                'timestamp': current['timestamp'],
                'details': current['hosts'][host]
            })
        
        for host in removed_hosts:
            changes.append({
                'type': 'host_disappeared',
                'host': host,
                'timestamp': current['timestamp'],
                'details': previous['hosts'][host]
            })
        
        # Detect new services
        current_services = set(current['services'].keys())
        previous_services = set(previous['services'].keys())
        
        new_services = current_services - previous_services
        
        for service in new_services:
            changes.append({
                'type': 'new_service',
                'service': service,
                'timestamp': current['timestamp'],
                'details': current['services'][service]
            })
        
        return changes
    
    def export_topology(self, filename: str = None) -> str:
        """Export network topology to file"""
        if not filename:
            filename = f"network_topology_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        if not self.topology_history:
            return None
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'current_topology': self.topology_history[-1],
            'topology_changes': self.detect_topology_changes(),
            'metadata': {
                'total_snapshots': len(self.topology_history),
                'first_snapshot': self.topology_history[0]['timestamp'] if self.topology_history else None,
                'last_snapshot': self.topology_history[-1]['timestamp'] if self.topology_history else None
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return filename
        except Exception as e:
            print(f"Error exporting topology: {e}")
            return None

def main():
    """Test network topology mapper"""
    mapper = NetworkTopologyMapper()
    
    # Sample network packets
    sample_packets = [
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dest_ip': '8.8.8.8',
            'src_port': 12345,
            'dest_port': 443,
            'protocol': 'TCP',
            'size': 1024
        },
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.101',
            'dest_ip': '192.168.1.1',
            'src_port': 54321,
            'dest_port': 80,
            'protocol': 'TCP',
            'size': 512
        }
    ]
    
    # Discover topology
    topology = mapper.discover_network_topology(sample_packets)
    print(f"Discovered topology with {len(topology['hosts'])} hosts")
    
    # Export topology
    filename = mapper.export_topology()
    if filename:
        print(f"Topology exported to: {filename}")

if __name__ == "__main__":
    main()