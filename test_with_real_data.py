# test_with_real_data.py
from security_monitor import SecurityMonitor, SecurityDashboard
from scapy.all import *
import threading
import time

class TestDataRunner:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.monitor = SecurityMonitor()
        self.dashboard = SecurityDashboard(self.monitor)

    def replay_packets(self):
        """Replay packets from PCAP file"""
        packets = rdpcap(self.pcap_file)
        print(f"Loaded {len(packets)} packets from {self.pcap_file}")
        
        for packet in packets:
            self.monitor._packet_callback(packet)
            time.sleep(0.01)  # Simulate real-time capture

    def run_test(self):
        """Run test with real data"""
        # Start packet replay in background
        replay_thread = threading.Thread(target=self.replay_packets)
        replay_thread.daemon = True
        replay_thread.start()
        
        # Start dashboard
        self.dashboard.run()

def main():
    # Email configuration for testing
    email_config = {
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587,
        'username': 'hackathon598@gmail.com',
        'password': '4orth3c0in',  # Use App Password from Google Account
        'from': 'hackathon598@gmail.com',
        'to': 'hackathon598@gmail.com'
    }

    # Test with normal traffic
    runner = TestDataRunner("sample_data/ddos_attack.pcap")
    runner.monitor.email_config = email_config  # Add email config
    runner.run_test()
