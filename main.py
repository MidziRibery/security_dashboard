### main.py - Entry Point for the Network Security Monitoring System

from security_monitor import SecurityMonitor
from gui.security_dashboard import SecurityDashboard
from test_with_real_data import TestDataRunner
import sys

def main():
    # Initialize the security monitor
    monitor = SecurityMonitor()

    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        # Run with test PCAP file
        print("Running with test PCAP file...")
        runner = TestDataRunner("sample_data/ddos_attack_10000.pcap")
        runner.run_test()
    else:
        # Start live packet capture
        print("Starting live packet capture (requires admin/root privileges)...")
        monitor.start_capture()

        # Initialize and run the security dashboard
        print("Launching Security Dashboard...")
        dashboard = SecurityDashboard(monitor)
        dashboard.run()

if __name__ == "__main__":
    main()
