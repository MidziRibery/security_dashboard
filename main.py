### main.py - Entry Point for the Network Security Monitoring System

from security_monitor import SecurityMonitor
from gui.security_dashboard import SecurityDashboard

def main():
    # Initialize the security monitor
    monitor = SecurityMonitor()

    # Start packet capture
    print("Starting packet capture...")
    monitor.start_capture()

    # Initialize and run the security dashboard
    print("Launching Security Dashboard...")
    dashboard = SecurityDashboard(monitor)
    dashboard.run()

if __name__ == "__main__":
    main()
