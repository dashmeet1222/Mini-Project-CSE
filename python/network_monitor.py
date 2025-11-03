#!/usr/bin/env python3
"""
Real-time Network Traffic Monitor
Captures and analyzes network packets for intrusion detection
"""

import socket
import struct
import json
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
import sys

class NetworkMonitor:
    def __init__(self, interface='eth0', max_packets=1000):
        self.interface = interface
        self.max_packets = max_packets
        self.packet_buffer = deque(maxlen=max_packets)
        self.traffic_stats = defaultdict(int)
        self.is_monitoring = False
        self.monitor_thread = None
        
    def create_socket(self):
        """Create raw socket for packet capture"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            return sock
        except PermissionError:
            print("Error: Root privileges required for packet capture")
            return None
        except Exception as e:
            print(f"Error creating socket: {e}")
            return None
    
    def parse_ethernet_header(self, packet):
        """Parse Ethernet header"""
        eth_header = struct.unpack('!6s6sH', packet[:14])
        dest_mac = ':'.join(f'{b:02x}' for b in eth_header[0])
        src_mac = ':'.join(f'{b:02x}' for b in eth_header[1])
        eth_type = eth_header[2]
        
        return {
            'dest_mac': dest_mac,
            'src_mac': src_mac,
            'type': eth_type,
            'payload': packet[14:]
        }
    
    def parse_ip_header(self, packet):
        """Parse IP header"""
        if len(packet) < 20:
            return None
            
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        
        version = ip_header[0] >> 4
        ihl = (ip_header[0] & 0xF) * 4
        ttl = ip_header[5]
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        
        return {
            'version': version,
            'header_length': ihl,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dest_ip': dest_ip,
            'payload': packet[ihl:]
        }
    
    def parse_tcp_header(self, packet):
        """Parse TCP header"""
        if len(packet) < 20:
            return None
            
        tcp_header = struct.unpack('!HHLLBBHHH', packet[:20])
        
        src_port = tcp_header[0]
        dest_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        flags = tcp_header[5]
        window = tcp_header[6]
        
        return {
            'src_port': src_port,
            'dest_port': dest_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'flags': flags,
            'window': window
        }
    
    def parse_udp_header(self, packet):
        """Parse UDP header"""
        if len(packet) < 8:
            return None
            
        udp_header = struct.unpack('!HHHH', packet[:8])
        
        return {
            'src_port': udp_header[0],
            'dest_port': udp_header[1],
            'length': udp_header[2],
            'checksum': udp_header[3]
        }
    
    def analyze_packet(self, packet):
        """Analyze captured packet"""
        try:
            timestamp = datetime.now().isoformat()
            packet_size = len(packet)
            
            # Parse Ethernet header
            eth_data = self.parse_ethernet_header(packet)
            
            # Check if it's an IP packet
            if eth_data['type'] == 0x0800:  # IPv4
                ip_data = self.parse_ip_header(eth_data['payload'])
                if not ip_data:
                    return None
                
                packet_info = {
                    'timestamp': timestamp,
                    'size': packet_size,
                    'src_ip': ip_data['src_ip'],
                    'dest_ip': ip_data['dest_ip'],
                    'protocol': 'Unknown',
                    'src_port': None,
                    'dest_port': None,
                    'flags': None
                }
                
                # Parse transport layer
                if ip_data['protocol'] == 6:  # TCP
                    tcp_data = self.parse_tcp_header(ip_data['payload'])
                    if tcp_data:
                        packet_info.update({
                            'protocol': 'TCP',
                            'src_port': tcp_data['src_port'],
                            'dest_port': tcp_data['dest_port'],
                            'flags': tcp_data['flags']
                        })
                        
                        # Determine application protocol
                        if tcp_data['dest_port'] == 80 or tcp_data['src_port'] == 80:
                            packet_info['protocol'] = 'HTTP'
                        elif tcp_data['dest_port'] == 443 or tcp_data['src_port'] == 443:
                            packet_info['protocol'] = 'HTTPS'
                        elif tcp_data['dest_port'] == 22 or tcp_data['src_port'] == 22:
                            packet_info['protocol'] = 'SSH'
                
                elif ip_data['protocol'] == 17:  # UDP
                    udp_data = self.parse_udp_header(ip_data['payload'])
                    if udp_data:
                        packet_info.update({
                            'protocol': 'UDP',
                            'src_port': udp_data['src_port'],
                            'dest_port': udp_data['dest_port']
                        })
                        
                        # Determine application protocol
                        if udp_data['dest_port'] == 53 or udp_data['src_port'] == 53:
                            packet_info['protocol'] = 'DNS'
                
                # Update statistics
                self.traffic_stats['total_packets'] += 1
                self.traffic_stats['total_bytes'] += packet_size
                self.traffic_stats[packet_info['protocol']] += 1
                
                return packet_info
                
        except Exception as e:
            print(f"Error analyzing packet: {e}")
            return None
    
    def monitor_traffic(self):
        """Main monitoring loop"""
        sock = self.create_socket()
        if not sock:
            return
        
        print(f"Starting network monitoring on interface {self.interface}")
        
        try:
            while self.is_monitoring:
                try:
                    packet, addr = sock.recvfrom(65535)
                    packet_info = self.analyze_packet(packet)
                    
                    if packet_info:
                        self.packet_buffer.append(packet_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving packet: {e}")
                    break
                    
        finally:
            sock.close()
            print("Network monitoring stopped")
    
    def start_monitoring(self):
        """Start monitoring in a separate thread"""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self.monitor_traffic)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            return True
        return False
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        return True
    
    def get_recent_packets(self, count=10):
        """Get recent packets"""
        return list(self.packet_buffer)[-count:]
    
    def get_traffic_stats(self):
        """Get traffic statistics"""
        return dict(self.traffic_stats)
    
    def export_packets_json(self, filename=None):
        """Export packets to JSON file"""
        if not filename:
            filename = f"packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(list(self.packet_buffer), f, indent=2)
            return filename
        except Exception as e:
            print(f"Error exporting packets: {e}")
            return None

def main():
    """Main function for standalone execution"""
    monitor = NetworkMonitor()
    
    try:
        print("Starting network monitor...")
        monitor.start_monitoring()
        
        # Monitor for 30 seconds
        time.sleep(30)
        
        print("\nTraffic Statistics:")
        stats = monitor.get_traffic_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print(f"\nRecent packets: {len(monitor.get_recent_packets())}")
        
        # Export packets
        filename = monitor.export_packets_json()
        if filename:
            print(f"Packets exported to: {filename}")
        
    except KeyboardInterrupt:
        print("\nStopping monitor...")
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()