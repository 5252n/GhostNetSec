from scapy.all import sniff, IP, TCP, UDP, ARP, Ether
from datetime import datetime
import threading
from collections import defaultdict
import time
from .app import app, log_event

class NetworkAnalyzer:
    def __init__(self):
        self.running = False
        self.thread = None
        self.packet_count = 0
        self.traffic_stats = defaultdict(int)
        self.protocol_stats = defaultdict(int)
        self.suspicious_activity = []
        self.known_devices = set()
    
    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._run)
            self.thread.daemon = True
            self.thread.start()
            app.logger.info("Network analyzer started")
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join()
        app.logger.info("Network analyzer stopped")
    
    def _run(self):
        """Main analysis loop"""
        try:
            # Start packet capture
            sniff(prn=self._process_packet, 
                 filter="ip or arp",
                 store=False,
                 stop_filter=lambda x: not self.running)
        except Exception as e:
            app.logger.error(f"Packet capture error: {str(e)}")
    
    def _process_packet(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        
        # Record basic stats
        timestamp = datetime.utcnow().isoformat()
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update traffic stats
            self.traffic_stats[(src_ip, dst_ip)] += 1
            
            if TCP in packet:
                self.protocol_stats['tcp'] += 1
                self._analyze_tcp(packet, timestamp)
            elif UDP in packet:
                self.protocol_stats['udp'] += 1
                self._analyze_udp(packet, timestamp)
        
        elif ARP in packet:
            self.protocol_stats['arp'] += 1
            self._analyze_arp(packet, timestamp)
    
    def _analyze_tcp(self, packet, timestamp):
        """Analyze TCP packets for suspicious activity"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Check for port scanning
        if dst_port in [22, 3389, 5900] and flags == 'S':  # SYN to common admin ports
            self._record_suspicious_activity(
                src_ip, 
                f"TCP SYN to {dst_ip}:{dst_port}",
                timestamp
            )
        
        # Check for unusual flag combinations
        if flags == 0:  # NULL scan
            self._record_suspicious_activity(
                src_ip,
                f"TCP NULL scan to {dst_ip}:{dst_port}",
                timestamp
            )
        elif 'F' in flags and 'S' in flags:  # SYN+FIN
            self._record_suspicious_activity(
                src_ip,
                f"TCP SYN+FIN to {dst_ip}:{dst_port}",
                timestamp
            )
    
    def _analyze_udp(self, packet, timestamp):
        """Analyze UDP packets for suspicious activity"""
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[UDP].dport
        
        # Check for DNS amplification attempts
        if dst_port == 53 and len(packet) > 512:  # Large DNS query
            self._record_suspicious_activity(
                src_ip,
                f"Large DNS query to {dst_ip}:{dst_port}",
                timestamp
            )
    
    def _analyze_arp(self, packet, timestamp):
        """Analyze ARP packets for suspicious activity"""
        # Check for ARP spoofing
        if packet[ARP].op == 2:  # ARP reply
            src_mac = packet[Ether].src
            src_ip = packet[ARP].psrc
            
            # Check if this MAC is claiming multiple IPs
            if src_mac in self.known_devices:
                if src_ip not in [ip for mac, ip in self.known_devices if mac == src_mac]:
                    self._record_suspicious_activity(
                        src_ip,
                        f"Possible ARP spoofing: {src_mac} claiming {src_ip}",
                        timestamp
                    )
            else:
                self.known_devices.add((src_mac, src_ip))
    
    def _record_suspicious_activity(self, src_ip, description, timestamp):
        """Record suspicious activity and create alert"""
        self.suspicious_activity.append({
            'src_ip': src_ip,
            'description': description,
            'timestamp': timestamp
        })
        
        # Log event
        log_event(None, 'suspicious_activity', description)
        
        # TODO: Add to database and emit Socket.IO event
    
    def get_stats(self):
        """Get current statistics"""
        return {
            'packet_count': self.packet_count,
            'traffic_stats': dict(self.traffic_stats),
            'protocol_stats': dict(self.protocol_stats),
            'suspicious_activity': self.suspicious_activity[-10:]  # Last 10 events
        }