### security_monitor.py - Core Network Monitoring Logic

import threading
import time
from scapy.config import conf
from scapy.arch import get_if_list
from scapy.layers.inet import IP
from scapy.utils import wrpcap, rdpcap
from collections import defaultdict, deque
from datetime import datetime
import platform
from enum import Enum
from dataclasses import dataclass
from typing import Dict, Optional
import smtplib
from email.mime.text import MIMEText

# Platform-specific interface handling
if platform.system() == "Windows":
    from scapy.arch.windows import get_windows_if_list
else:
    def get_windows_if_list():
        raise NotImplementedError("get_windows_if_list is only available on Windows")

# Alert Severity Levels
class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class Alert:
    timestamp: str
    message: str
    severity: AlertSeverity
    source_ip: str
    category: str
    details: Dict

# Thresholds and size limits
PACKET_THRESHOLD = 100
CONNECTION_THRESHOLD = 20
PORT_SCAN_THRESHOLD = 10
SIZE_THRESHOLDS = {
    'jumbo': 9000,
    'suspicious': 1000,
    'tiny': 64
}

class SecurityMonitor:
    def __init__(self, email_config: Optional[Dict] = None):
        self.packet_counts = defaultdict(int)
        self.email_config = email_config
        self.connection_history = defaultdict(lambda: deque(maxlen=100000))
        self.suspicious_ips = set()
        self.packet_queue = deque(maxlen=100000)
        self.stats = {'alerts': []}  # Initialize stats dictionary
        self.protocol_stats = defaultdict(int)
        self.filters = []
        self.detailed_packets = deque(maxlen=100000)
        self.platform = platform.system()
        
        # PPS monitoring
        self.pps_history = deque(maxlen=30)  # 3 minutes of per-second data
        self.last_pps_check = time.time()
        self.last_alert_time = defaultdict(float)
        self.PPS_THRESHOLDS = {
            'LOW': (100, 200),
            'MODERATE': (300, 500),
            'CRITICAL': 600
        }

        # Initialize size tracking
        self.size_stats = {
            'min_size': float('inf'),
            'max_size': 0,
            'avg_size': 0,
            'total_size': 0,
            'size_distribution': defaultdict(int),
        }

        try:
            if not conf.use_npcap:
                print("Warning: Npcap not detected. Please install Npcap from https://npcap.com/")
                print("Falling back to default socket capture...")
                conf.use_pcap = False
        except Exception as e:
            print(f"Error configuring Scapy: {e}")
            print("Defaulting to basic socket capture...")

    def start_capture(self):
        """Start packet capture in a separate thread"""
        self.capture_thread = threading.Thread(target=self._packet_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def _get_network_interface(self):
        """Get suitable network interface based on platform"""
        if self.platform == "Darwin":  # macOS
            interfaces = get_if_list()
            for iface in interfaces:
                if not iface.startswith(('utun', 'awdl', 'llw', 'bridge')):
                    return iface
        elif self.platform == "Windows":
            interfaces = get_windows_if_list()
            if interfaces:
                return interfaces[0]['name']
        return None

    def _packet_capture(self):
        """Capture and analyze network packets"""
        try:
            interface = self._get_network_interface()
            if interface:
                print(f"Capturing on interface: {interface}")
                scapy.sniff(iface=interface, prn=self._packet_callback, store=False)
            else:
                print("No suitable interface found, using default")
                scapy.sniff(prn=self._packet_callback, store=False)
        except Exception as e:
            self._generate_alert(f"Capture error: {e}")

    def _packet_callback(self, packet):
        """Process each captured packet"""
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst

            # Update packet counts
            self.packet_counts[ip_src] += 1
            self.stats['total_packets'] = len(self.packet_queue)

            # Store packet info
            packet_info = {
                'timestamp': time.time(),
                'src': ip_src,
                'dst': ip_dst,
                'size': len(packet),
                'protocol': packet[IP].proto
            }

            self.packet_queue.append(packet_info)
            self._check_suspicious_activity(ip_src, packet_info)
            self._update_size_stats(len(packet))
            self._check_pps_thresholds()

    def _check_suspicious_activity(self, ip_src, packet_info):
        """Analyze packets for suspicious patterns"""
        if self.packet_counts[ip_src] > PACKET_THRESHOLD:
            self._generate_alert(f"High packet rate detected from {ip_src}")
            self.suspicious_ips.add(ip_src)

    def _update_size_stats(self, packet_size):
        """Update packet size statistics"""
        self.size_stats['min_size'] = min(self.size_stats['min_size'], packet_size)
        self.size_stats['max_size'] = max(self.size_stats['max_size'], packet_size)
        self.size_stats['total_size'] += packet_size
        self.size_stats['avg_size'] = self.size_stats['total_size'] / len(self.packet_queue)

        size_range = (packet_size // 100) * 100
        self.size_stats['size_distribution'][size_range] += 1

    def _check_pps_thresholds(self):
        """Monitor packets per second and trigger alerts based on thresholds"""
        current_time = time.time()
        
        # Calculate current PPS
        recent_packets = sum(1 for p in self.packet_queue if current_time - p['timestamp'] <= 1.0)
        self.pps_history.append(recent_packets)
        
        # Only check every second
        if current_time - self.last_pps_check < 1.0:
            return
        self.last_pps_check = current_time
        
        # Calculate average PPS over 3 minutes
        if len(self.pps_history) >= 180:  # 3 minutes of data
            avg_pps = sum(self.pps_history) / len(self.pps_history)
            
            # Check thresholds
            if avg_pps >= self.PPS_THRESHOLDS['CRITICAL']:
                if current_time - self.last_alert_time['CRITICAL'] > 180:  # Alert every 3 minutes
                    self._generate_alert(f"CRITICAL: Extremely high traffic detected! Average PPS: {avg_pps:.0f}", 
                                      severity=AlertSeverity.CRITICAL)
                    self.last_alert_time['CRITICAL'] = current_time
            elif self.PPS_THRESHOLDS['MODERATE'][0] <= avg_pps <= self.PPS_THRESHOLDS['MODERATE'][1]:
                if current_time - self.last_alert_time['MODERATE'] > 180:
                    self._generate_alert(f"MODERATE: High traffic levels detected. Average PPS: {avg_pps:.0f}", 
                                      severity=AlertSeverity.MEDIUM)
                    self.last_alert_time['MODERATE'] = current_time
            elif self.PPS_THRESHOLDS['LOW'][0] <= avg_pps <= self.PPS_THRESHOLDS['LOW'][1]:
                if current_time - self.last_alert_time['LOW'] > 180:
                    self._generate_alert(f"WARNING: Elevated traffic levels. Average PPS: {avg_pps:.0f}", 
                                      severity=AlertSeverity.LOW)
                    self.last_alert_time['LOW'] = current_time

    def _generate_alert(self, message, severity=AlertSeverity.MEDIUM):
        """Generate security alert"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = f"[{timestamp}] {message}"
        self.stats['alerts'].append(alert)
        print(alert)  # Immediate console output
        
        # Send email alert if configured
        if self.email_config:
            try:
                msg = MIMEText(alert)
                msg['Subject'] = f'Security Alert - {severity.value.upper()}'
                msg['From'] = self.email_config['from']
                msg['To'] = self.email_config['to']
                
                with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                    server.starttls()
                    server.login(self.email_config['username'], self.email_config['password'])
                    server.send_message(msg)
            except Exception as e:
                print(f"Failed to send email alert: {e}")

    def save_capture(self, filename):
        """Save packet capture to file"""
        if self.packet_queue:
            wrpcap(filename, list(self.packet_queue))

    def load_capture(self, filename):
        """Load packet capture from file"""
        try:
            packets = rdpcap(filename)
            self.packet_queue.extend(packets)
        except Exception as e:
            self._generate_alert(f"Failed to load capture: {e}")
