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
    # Use real PCAP files
    test_files = [
        "sample_data/normal_traffic.pcap",  # Normal traffic
        "sample_data/port_scan.pcap",       # Port scan attack
        "sample_data/ddos.pcap"            # DDoS attack
    ]
    
    for test_file in test_files:
        runner = TestDataRunner(test_file)
        runner.run_test()