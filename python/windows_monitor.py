#!/usr/bin/env python3
"""
Windows Network Monitor
Real-time network packet capture for Windows systems using Npcap/WinPcap
"""

import socket
import struct
import json
import time
import threading
import platform
from datetime import datetime
from collections import defaultdict, deque
import subprocess
import sys

class WindowsNetworkMonitor:
    def __init__(self, interface=None, max_packets=1000):
        self.interface = interface or self.get_default_interface()
        self.max_packets = max_packets
        self.packet_buffer = deque(maxlen=max_packets)
        self.traffic_stats = defaultdict(int)
        self.is_monitoring = False
        self.monitor_thread = None
        self.use_scapy = self.check_scapy_available()
        
    def check_scapy_available(self):
        """Check if Scapy is available for packet capture"""
        try:
            import scapy
            return True
        except ImportError:
            print("Scapy not available. Install with: pip install scapy")
            return False
    
    def get_default_interface(self):
        """Get the default network interface on Windows"""
        try:
            # Get default gateway interface
            result = subprocess.run(['route', 'print', '0.0.0.0'], 
                                  capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line and 'On-link' not in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[3]  # Interface IP
            return "127.0.0.1"  # Fallback to localhost
        except Exception as e:
            print(f"Error getting default interface: {e}")
            return "127.0.0.1"
    
    def get_network_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_adapter = None
                for line in lines:
                    line = line.strip()
                    if 'adapter' in line.lower():
                        current_adapter = line
                    elif 'IPv4 Address' in line and current_adapter:
                        ip = line.split(':')[-1].strip()
                        interfaces.append({
                            'name': current_adapter,
                            'ip': ip
                        })
        except Exception as e:
            print(f"Error getting interfaces: {e}")
        
        return interfaces
    
    def create_raw_socket(self):
        """Create raw socket for Windows packet capture"""
        try:
            # Windows raw socket creation
            if platform.system() == "Windows":
                # Create raw socket (requires admin privileges)
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((self.interface, 0))
                
                # Enable promiscuous mode
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                return sock
            else:
                # Linux/Unix raw socket
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                return sock
        except PermissionError:
            print("Error: Administrator privileges required for packet capture on Windows")
            print("Please run as Administrator or install Npcap/WinPcap")
            return None
        except Exception as e:
            print(f"Error creating raw socket: {e}")
            return None
    
    def monitor_with_scapy(self):
        """Monitor network traffic using Scapy (recommended for Windows)"""
        try:
            from scapy.all import sniff, IP, TCP, UDP
            
            def packet_handler(packet):
                if IP in packet:
                    packet_info = self.parse_scapy_packet(packet)
                    if packet_info:
                        self.packet_buffer.append(packet_info)
                        self.update_stats(packet_info)
            
            print(f"Starting Scapy packet capture on interface: {self.interface}")
            # Capture packets on all interfaces if no specific interface
            sniff(prn=packet_handler, store=0, stop_filter=lambda x: not self.is_monitoring)
            
        except ImportError:
            print("Scapy not installed. Install with: pip install scapy")
            return False
        except Exception as e:
            print(f"Error in Scapy monitoring: {e}")
            return False
        
        return True
    
    def parse_scapy_packet(self, packet):
        """Parse packet using Scapy"""
        try:
            from scapy.all import IP, TCP, UDP, ICMP
            
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            timestamp = datetime.now().isoformat()
            
            packet_info = {
                'timestamp': timestamp,
                'size': len(packet),
                'src_ip': ip_layer.src,
                'dest_ip': ip_layer.dst,
                'protocol': 'Unknown',
                'src_port': None,
                'dest_port': None,
                'flags': None
            }
            
            # Parse transport layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info.update({
                    'protocol': 'TCP',
                    'src_port': tcp_layer.sport,
                    'dest_port': tcp_layer.dport,
                    'flags': tcp_layer.flags
                })
                
                # Determine application protocol
                if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                    packet_info['protocol'] = 'HTTP'
                elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                    packet_info['protocol'] = 'HTTPS'
                elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
                    packet_info['protocol'] = 'SSH'
                    
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info.update({
                    'protocol': 'UDP',
                    'src_port': udp_layer.sport,
                    'dest_port': udp_layer.dport
                })
                
                if udp_layer.dport == 53 or udp_layer.sport == 53:
                    packet_info['protocol'] = 'DNS'
                    
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
            
            return packet_info
            
        except Exception as e:
            print(f"Error parsing Scapy packet: {e}")
            return None
    
    def monitor_with_raw_socket(self):
        """Monitor using raw sockets (requires admin privileges)"""
        sock = self.create_raw_socket()
        if not sock:
            return False
        
        print(f"Starting raw socket packet capture on {self.interface}")
        
        try:
            while self.is_monitoring:
                try:
                    packet, addr = sock.recvfrom(65535)
                    packet_info = self.parse_raw_packet(packet)
                    
                    if packet_info:
                        self.packet_buffer.append(packet_info)
                        self.update_stats(packet_info)
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error receiving packet: {e}")
                    break
                    
        finally:
            if platform.system() == "Windows":
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            print("Raw socket monitoring stopped")
        
        return True
    
    def parse_raw_packet(self, packet):
        """Parse raw packet data"""
        try:
            # Parse IP header (Windows raw sockets start with IP header)
            if len(packet) < 20:
                return None
                
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
            
            version = ip_header[0] >> 4
            if version != 4:  # Only IPv4 for now
                return None
            
            ihl = (ip_header[0] & 0xF) * 4
            protocol = ip_header[6]
            src_ip = socket.inet_ntoa(ip_header[8])
            dest_ip = socket.inet_ntoa(ip_header[9])
            
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'size': len(packet),
                'src_ip': src_ip,
                'dest_ip': dest_ip,
                'protocol': 'Unknown',
                'src_port': None,
                'dest_port': None,
                'flags': None
            }
            
            # Parse transport layer
            if protocol == 6:  # TCP
                if len(packet) >= ihl + 20:
                    tcp_header = struct.unpack('!HHLLBBHHH', packet[ihl:ihl+20])
                    packet_info.update({
                        'protocol': 'TCP',
                        'src_port': tcp_header[0],
                        'dest_port': tcp_header[1],
                        'flags': tcp_header[5]
                    })
                    
            elif protocol == 17:  # UDP
                if len(packet) >= ihl + 8:
                    udp_header = struct.unpack('!HHHH', packet[ihl:ihl+8])
                    packet_info.update({
                        'protocol': 'UDP',
                        'src_port': udp_header[0],
                        'dest_port': udp_header[1]
                    })
            
            return packet_info
            
        except Exception as e:
            print(f"Error parsing raw packet: {e}")
            return None
    
    def update_stats(self, packet_info):
        """Update traffic statistics"""
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['total_bytes'] += packet_info['size']
        self.traffic_stats[packet_info['protocol']] += 1
    
    def start_monitoring(self):
        """Start network monitoring"""
        if self.is_monitoring:
            return True
        
        self.is_monitoring = True
        
        # Try Scapy first (recommended for Windows)
        if self.use_scapy:
            self.monitor_thread = threading.Thread(target=self.monitor_with_scapy)
        else:
            self.monitor_thread = threading.Thread(target=self.monitor_with_raw_socket)
        
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
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
            filename = f"packets_windows_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(list(self.packet_buffer), f, indent=2)
            return filename
        except Exception as e:
            print(f"Error exporting packets: {e}")
            return None

def main():
    """Main function for testing Windows network monitoring"""
    print("Windows Network Monitor")
    print("=" * 50)
    
    monitor = WindowsNetworkMonitor()
    
    # Show available interfaces
    interfaces = monitor.get_network_interfaces()
    print("Available network interfaces:")
    for i, interface in enumerate(interfaces):
        print(f"  {i+1}. {interface['name']} - {interface['ip']}")
    
    try:
        print(f"\nStarting monitoring on interface: {monitor.interface}")
        print("Press Ctrl+C to stop...")
        
        success = monitor.start_monitoring()
        if not success:
            print("Failed to start monitoring. Try running as Administrator.")
            return
        
        # Monitor for 30 seconds
        time.sleep(30)
        
        print("\nTraffic Statistics:")
        stats = monitor.get_traffic_stats()
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        print(f"\nCaptured packets: {len(monitor.get_recent_packets())}")
        
        # Export packets
        filename = monitor.export_packets_json()
        if filename:
            print(f"Packets exported to: {filename}")
        
    except KeyboardInterrupt:
        print("\nStopping monitor...")
    finally:
        monitor.stop_monitoring()
        print("Monitor stopped.")

if __name__ == "__main__":
    main()