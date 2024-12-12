# Network Security Monitoring Dashboard

Real-time network traffic analyzer with ML-powered threat detection and visualization.

## Features
- 🔍 Real-time packet capture and analysis
- 🤖 Machine Learning based threat detection
- 📊 Interactive visualization dashboard
- 🚨 Automated alert system
- 🔬 Protocol analysis
- 💾 PCAP file import/export
- 📈 Traffic statistics

## Installation

### Prerequisites
- Python 3.8+
- Npcap (Windows) or libpcap (Unix)
- Admin/root privileges for packet capture

### Setup
```bash
# Clone repository
git clone https://github.com/yourusername/network-security-monitor.git
cd network-security-monitor

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Unix
# or
.venv\Scripts\activate  # On Windows

# Install dependencies
pip install -r [requirements.txt]

Dependencies
scapy>=2.5.0
numpy>=1.24.0
pandas>=2.0.0
scikit-learn>=1.2.0
matplotlib>=3.7.0
tkinter>=8.6

# On Unix/Mac
sudo python security_monitor.py

# On Windows (run as Administrator)
python security_monitor.py