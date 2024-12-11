import threading
import time
import tkinter as tk
from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import scapy.all as scapy
from scapy.config import conf 
from scapy.arch import get_if_list
from scapy.layers.inet import IP
import platform
from collections import defaultdict, deque
from datetime import datetime
from scapy.layers import all as scapy_layers
from scapy.utils import wrpcap, rdpcap
import json
import os
import requests
from dataclasses import dataclass
from enum import Enum
import numpy as np
from sklearn.ensemble import IsolationForest
import pandas as pd
from typing import Dict, List, Optional
import logging
from tkinter import filedialog

if platform.system() == "Windows":
    from scapy.arch.windows import get_windows_if_list
else:
    # Provide an alternative or handle the absence of get_windows_if_list
    def get_windows_if_list():
        raise NotImplementedError("get_windows_if_list is only available on Windows")

# ml/threat_detection.py
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Any

class ThreatDetectionEngine:
    def __init__(self):
        self.feature_columns = [
            'packet_size',
            'protocol',
            'flags',
            'packet_rate', 
            'flow_duration',
            'bytes_per_second',
            'packets_per_second',
            'avg_packet_size',
            'port_entropy',
            'ip_entropy'
        ]
        self.models = {
            'anomaly': IsolationForest(contamination=0.1, random_state=42),
            'classifier': RandomForestClassifier(n_estimators=100, random_state=42),
            'behavior': IsolationForest(contamination=0.05, random_state=42)
        }
        self.scaler = StandardScaler()
        self._initialize_default_models()

    def extract_features(self, packet: Dict) -> pd.DataFrame:
        """Extract features ensuring consistent column names"""
        data = []
        features = {col: 0 for col in self.feature_columns}  # Initialize with zeros
        
        # Update with actual values
        features.update({
            'packet_size': len(packet),
            'protocol': hash(packet.get('protocol', 0)) % 100,
            'flags': len(packet.get('flags', [])),
            'packet_rate': packet.get('packet_rate', 0),
            'flow_duration': packet.get('flow_duration', 0),
            'bytes_per_second': packet.get('bytes_per_second', 0),
            'packets_per_second': packet.get('packets_per_second', 0),
            'avg_packet_size': packet.get('avg_packet_size', 0),
            'port_entropy': self._calculate_entropy(packet.get('ports', [])),
            'ip_entropy': self._calculate_entropy(packet.get('ips', []))
        })
        data.append(features)
        return pd.DataFrame(data, columns=self.feature_columns)

    def predict_threat(self, packet: Dict) -> Dict[str, Any]:
        """Predict threat ensuring feature names match"""
        features_df = self.extract_features(packet)
        assert all(col in features_df.columns for col in self.feature_columns), "Missing features"
        
        scaled_features = self.scaler.transform(features_df)
        scaled_df = pd.DataFrame(scaled_features, columns=self.feature_columns)
        
        predictions = {
            'anomaly_score': self.models['anomaly'].score_samples(scaled_df)[0],
            'classification': self.models['classifier'].predict(scaled_df)[0],
            'behavior_score': self.models['behavior'].score_samples(scaled_df)[0]
        }
        
        return {
            **predictions,
            'threat_score': self._calculate_threat_score(predictions),
            'is_threat': self._calculate_threat_score(predictions) > 0.7
        }

    def _initialize_default_models(self):
        """Initialize models and scaler with default values"""
        # Create sample data
        sample_data = pd.DataFrame({
            'packet_size': [100, 200, 1500, 64, 1000],
            'protocol': [6, 17, 1, 6, 17],
            'flags': [1, 2, 0, 1, 2],
            'packet_rate': [10, 20, 5, 15, 25],
            'flow_duration': [1.0, 2.0, 0.5, 1.5, 2.5],
            'bytes_per_second': [1000, 2000, 500, 1500, 2500],
            'packets_per_second': [10, 20, 5, 15, 25],
            'avg_packet_size': [100, 150, 200, 80, 160],
            'port_entropy': [0.5, 0.7, 0.3, 0.6, 0.8],
            'ip_entropy': [0.3, 0.4, 0.2, 0.5, 0.6]
        })
        
        # Fit scaler with sample data
        self.scaler.fit(sample_data)
        
        # Train models with basic labels
        sample_labels = [0, 0, 1, 0, 1]  # 0: normal, 1: anomaly
        
        # Train models
        self.models['anomaly'].fit(sample_data)
        self.models['classifier'].fit(sample_data, sample_labels)
        self.models['behavior'].fit(sample_data)
        
        # Save initialized models
        os.makedirs('models', exist_ok=True)
        for name, model in self.models.items():
            joblib.dump(model, f'models/{name}_model.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')
        
    def _calculate_entropy(self, values: List) -> float:
        """Calculate Shannon entropy for a list of values"""
        if not values:
            return 0.0
        value_counts = pd.Series(values).value_counts(normalize=True)
        return -(value_counts * np.log2(value_counts)).sum()
        
    def _calculate_threat_score(self, predictions: Dict) -> float:
        """Calculate overall threat score"""
        weights = {
            'anomaly': 0.4,
            'classification': 0.4,
            'behavior': 0.2
        }
        
        score = (
            weights['anomaly'] * (1 - np.exp(predictions['anomaly_score'])) +
            weights['classification'] * float(predictions['classification']) +
            weights['behavior'] * (1 - np.exp(predictions['behavior_score']))
        )
        return float(score)
        
    def train(self, training_data: pd.DataFrame) -> None:
        """Train ML models with labeled data"""
        X = training_data[self.feature_columns]
        y = training_data['is_threat']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train models
        self.models['anomaly'].fit(X_train_scaled)
        self.models['classifier'].fit(X_train_scaled, y_train)
        self.models['behavior'].fit(X_train_scaled)
        
        # Save models
        self._save_models()
        
    def _save_models(self) -> None:
        """Save trained models to disk"""
        for name, model in self.models.items():
            joblib.dump(model, f'models/{name}_model.pkl')
        joblib.dump(self.scaler, 'models/scaler.pkl')
        
    def load_models(self) -> None:
        """Load trained models from disk"""
        for name in self.models.keys():
            model_path = f'models/{name}_model.pkl'
            if os.path.exists(model_path):
                self.models[name] = joblib.load(model_path)
            else:
                print(f"Model {name} not found, using default initialization")
                
        scaler_path = 'models/scaler.pkl'
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        else:
            print("Scaler not found, using default initialization")

class SecurityMonitor:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.connection_history = defaultdict(lambda: deque(maxlen=2000))
        self.suspicious_ips = set()
        self.packet_queue = deque(maxlen=2000)
        self.stats = {'alerts': []}  # Initialize stats dictionary
        self.protocol_stats = defaultdict(int)
        self.filters = []
        self.capture_file = None
        self.detailed_packets = deque(maxlen=2000)
        
        try:
            # Configure Scapy for Npcap
            if not conf.use_npcap:
                print("Warning: Npcap not detected. Please install Npcap from https://npcap.com/")
                print("Falling back to default socket capture...")
                conf.use_pcap = False
        except Exception as e:
            print(f"Error configuring Scapy: {e}")
            print("Defaulting to basic socket capture...")
        
        # Initialize thresholds
        self.PACKET_THRESHOLD = 100  # packets per second
        self.CONNECTION_THRESHOLD = 20  # connections per second
        self.PORT_SCAN_THRESHOLD = 10  # unique ports per second
        
        # Initialize stats
        self.stats = {
            'total_packets': 0,
            'suspicious_packets': 0,
            'alerts': []
        }
        
        # Add size tracking
        self.size_stats = {
            'min_size': float('inf'),
            'max_size': 0,
            'avg_size': 0,
            'total_size': 0,
            'size_distribution': defaultdict(int),  # Track packet size ranges
        }
        
        # Size thresholds (in bytes)
        self.SIZE_THRESHOLDS = {
            'jumbo': 9000,        # Jumbo frame size
            'suspicious': 1000,    # Standard MTU
            'tiny': 64            # Minimum Ethernet frame
        }
        
        # Platform-specific interface handling
        self.platform = platform.system()
        
        # Add to existing init
        self.threat_detector = ThreatDetectionEngine()
        try:
            self.threat_detector.load_models()
        except FileNotFoundError:
            print("Models not found, initializing with default values...")
            # Train with sample data or use default models
            self.threat_detector._initialize_default_models()
        
    def start_capture(self):
        """Start packet capture in a separate thread"""
        self.capture_thread = threading.Thread(target=self._packet_capture)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def _get_network_interface(self):
        """Get suitable network interface based on platform"""
        if self.platform == "Darwin":  # macOS
            interfaces = get_if_list()
            # Filter out non-physical interfaces on macOS
            suitable_interface = None
            for iface in interfaces:
                # Skip virtual/problematic interfaces
                if not iface.startswith(('utun', 'awdl', 'llw', 'bridge')):
                    suitable_interface = iface
                    break
            return suitable_interface
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
            error_msg = f"Capture error: {e}"
            print(error_msg)
            self._generate_alert(error_msg)
        
    def _packet_callback(self, packet):
        """Process each captured packet"""
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            
            # Update packet counts
            self.packet_counts[ip_src] += 1
            current_time = time.time()
            
            # Store packet info
            packet_info = {
                'timestamp': current_time,
                'src': ip_src,
                'dst': ip_dst,
                'size': len(packet),
                'protocol': packet[scapy.IP].proto
            }
            
            self.packet_queue.append(packet_info)
            
            # Check for suspicious activity
            self._check_suspicious_activity(ip_src, packet_info)
            
            # Update stats
            self.stats['total_packets'] += 1
            
            packet_size = len(packet)
            self._update_size_stats(packet_size)
            
            packet_info['size_stats'] = {
                'current_size': packet_size,
                'avg_size': self.size_stats['avg_size'],
                'size_anomaly': packet_size > self.SIZE_THRESHOLDS['suspicious']
            }
            
            # Add to existing packet callback
            if packet.haslayer(scapy.IP):
                packet_data = self._prepare_packet_data(packet)
                threat_analysis = self.threat_detector.predict_threat(packet_data)
                
                if threat_analysis['is_threat']:
                    self._generate_alert(
                        message=f"ML-detected threat (score: {threat_analysis['threat_score']:.2f})",
                        severity=AlertSeverity.HIGH if threat_analysis['threat_score'] > 0.9 
                                else AlertSeverity.MEDIUM,
                        category="ML_THREAT",
                        details={
                            'packet_info': packet_data,
                            'threat_analysis': threat_analysis
                        }
                    )
            
    def _check_suspicious_activity(self, ip_src, packet_info):
        """Analyze packets for suspicious patterns"""
        # Check for high packet rates
        if self.packet_counts[ip_src] > self.PACKET_THRESHOLD:
            self._generate_alert(f"High packet rate detected from {ip_src}")
            self.suspicious_ips.add(ip_src)
            
        # Check for port scanning
        if ip_src in self.connection_history:
            unique_ports = len(set(conn['dst_port'] for conn in self.connection_history[ip_src]))
            if unique_ports > self.PORT_SCAN_THRESHOLD:
                self._generate_alert(f"Possible port scan detected from {ip_src}")
                self.suspicious_ips.add(ip_src)
                
    def _generate_alert(self, message):
        """Generate security alert"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert = f"[{timestamp}] {message}"
        self.stats['alerts'].append(alert)
        print(alert)  # For immediate console output
        
    def _update_size_stats(self, packet_size):
        """Update packet size statistics"""
        self.size_stats['min_size'] = min(self.size_stats['min_size'], packet_size)
        self.size_stats['max_size'] = max(self.size_stats['max_size'], packet_size)
        self.size_stats['total_size'] += packet_size
        self.size_stats['avg_size'] = self.size_stats['total_size'] / self.stats['total_packets']
        
        # Track size distribution in ranges
        size_range = (packet_size // 100) * 100  # Group in 100-byte ranges
        self.size_stats['size_distribution'][size_range] += 1
        
        # Check for size-based anomalies
        if packet_size > self.SIZE_THRESHOLDS['jumbo']:
            self._generate_alert(f"Oversized packet detected: {packet_size} bytes")
        elif packet_size < self.SIZE_THRESHOLDS['tiny']:
            self._generate_alert(f"Suspicious tiny packet: {packet_size} bytes")

    def save_capture(self, filename):
        """Save packet capture to file"""
        if self.packet_queue:
            wrpcap(filename, list(self.packet_queue))
            
    def load_capture(self, filename):
        """Load packet capture from file"""
        try:
            packets = rdpcap(filename)
            self.packet_queue.clear()
            self.packet_queue.extend(packets)
            return True
        except Exception as e:
            self._generate_alert(f"Failed to load capture: {e}")
            return False

    def add_filter(self, filter_str):
        """Add packet filter"""
        self.filters.append(filter_str)

    def _packet_matches_filters(self, packet):
        """Check if packet matches current filters"""
        if not self.filters:
            return True
            
        for filter_str in self.filters:
            try:
                if eval(f"packet.{filter_str}"):
                    return True
            except:
                continue
        return False

    def _prepare_packet_data(self, packet):
        """Prepare packet data for ML analysis"""
        return {
            'size': len(packet),
            'protocol': packet[IP].proto if IP in packet else 0,
            'flags': self._extract_flags(packet),
            'packet_rate': self._calculate_packet_rate(),
            'flow_duration': self._calculate_flow_duration(packet),
            'bytes_per_second': self._calculate_bytes_per_second(),
            'packets_per_second': self._calculate_packets_per_second(),
            'avg_packet_size': self._calculate_avg_packet_size(),
            'ports': self._extract_ports(packet),
            'ips': [packet[IP].src, packet[IP].dst] if IP in packet else []
        }

    def _extract_flags(self, packet):
        """Extract flags from packet"""
        flags = []
        if 'TCP' in packet:
            flags = [flag for flag in packet['TCP'].flags]
        return flags

    def _calculate_packet_rate(self):
        """Calculate current packet rate"""
        return len(self.packet_queue) / 60  # packets per minute

    def _calculate_flow_duration(self, packet):
        """Calculate flow duration"""
        if not self.packet_queue:
            return 0
        return time.time() - self.packet_queue[0]['timestamp']

    def _calculate_bytes_per_second(self):
        """Calculate bytes per second"""
        if not self.packet_queue:
            return 0
        total_bytes = sum(len(p) for p in self.packet_queue)
        duration = self._calculate_flow_duration(None)
        return total_bytes / duration if duration > 0 else 0

    def _calculate_packets_per_second(self):
        """Calculate packets per second"""
        if not self.packet_queue:
            return 0
        duration = self._calculate_flow_duration(None)
        return len(self.packet_queue) / duration if duration > 0 else 0

    def _calculate_avg_packet_size(self):
        """Calculate average packet size"""
        if not self.packet_queue:
            return 0
        return sum(len(p) for p in self.packet_queue) / len(self.packet_queue)

    def _extract_ports(self, packet):
        """Extract ports from packet"""
        ports = []
        if 'TCP' in packet:
            ports.extend([packet['TCP'].sport, packet['TCP'].dport])
        elif 'UDP' in packet:
            ports.extend([packet['UDP'].sport, packet['UDP'].dport])
        return ports

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

class EnhancedSecurityMonitor(SecurityMonitor):
    def __init__(self):
        super().__init__()
        self.threat_intel_cache = {}
        self.anomaly_detector = IsolationForest(contamination=0.1)
        self.flow_data = defaultdict(dict)
        self.alerts_db = []
        self.setup_logging()

    def setup_logging(self):
        """Configure logging for the security monitor"""
        logging.basicConfig(
            filename='security_monitor.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    async def check_threat_intelligence(self, ip_address: str) -> Dict:
        """Query threat intelligence for IP addresses"""
        if ip_address in self.threat_intel_cache:
            return self.threat_intel_cache[ip_address]

        try:
            # Example using AbuseIPDB API
            api_key = os.getenv('ABUSEIPDB_API_KEY')
            url = f"https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': api_key, 'Accept': 'application/json'}
            params = {'ipAddress': ip_address, 'maxAgeInDays': 30}
            
            response = requests.get(url, headers=headers, params=params)
            intel = response.json()
            
            self.threat_intel_cache[ip_address] = intel
            return intel
        except Exception as e:
            logging.error(f"Threat intelligence query failed: {e}")
            return {}

    def analyze_packet_protocols(self, packet) -> Dict:
        """Enhanced protocol analysis"""
        protocol_info = {
            'layers': [],
            'anomalies': [],
            'security_flags': []
        }

        # Analyze each protocol layer
        for layer in packet.layers():
            layer_info = {
                'name': layer.name,
                'fields': {},
                'security_issues': []
            }

            # Check for security-relevant flags
            if hasattr(layer, 'flags'):
                layer_info['flags'] = layer.flags

            # Protocol-specific checks
            if layer.name == 'TCP':
                if layer.flags.S and layer.flags.F:
                    layer_info['security_issues'].append('TCP SYN+FIN flags set')
            
            protocol_info['layers'].append(layer_info)

        return protocol_info

    def detect_anomalies(self, packet_data: Dict):
        """Detect traffic anomalies using machine learning"""
        features = [
            packet_data['size'],
            packet_data['protocol_number'],
            packet_data['flags_count']
        ]
        
        # Reshape for sklearn
        X = np.array(features).reshape(1, -1)
        
        # Predict anomaly (-1 for anomalies, 1 for normal)
        result = self.anomaly_detector.predict(X)
        
        if result[0] == -1:
            self.generate_alert(
                message="Traffic anomaly detected",
                severity=AlertSeverity.MEDIUM,
                category="ANOMALY",
                details=packet_data
            )

    def analyze_network_flow(self, packet):
        """Analyze network flows for behavioral patterns"""
        if IP in packet:
            flow_key = f"{packet[IP].src}:{packet[IP].dst}"
            
            # Update flow statistics
            if flow_key not in self.flow_data:
                self.flow_data[flow_key] = {
                    'start_time': packet.time,
                    'packet_count': 0,
                    'byte_count': 0,
                    'protocols': set()
                }
            
            flow = self.flow_data[flow_key]
            flow['packet_count'] += 1
            flow['byte_count'] += len(packet)
            flow['protocols'].add(packet.name)
            
            # Check for flow-based anomalies
            self._check_flow_anomalies(flow_key)

    def _check_flow_anomalies(self, flow_key: str):
        """Check for anomalies in network flows"""
        flow = self.flow_data[flow_key]
        
        # Check for potential data exfiltration
        if flow['byte_count'] > 1000000:  # 1MB threshold
            self.generate_alert(
                message="Possible data exfiltration detected",
                severity=AlertSeverity.HIGH,
                category="DATA_EXFIL",
                details=flow
            )

    def generate_alert(self, message: str, severity: AlertSeverity, 
                      category: str, details: Dict):
        """Generate structured security alerts"""
        alert = Alert(
            timestamp=datetime.now().isoformat(),
            message=message,
            severity=severity,
            source_ip=details.get('source_ip', 'unknown'),
            category=category,
            details=details
        )
        
        self.alerts_db.append(alert)
        logging.warning(f"Security Alert: {message} [Severity: {severity.value}]")
        
        # Trigger immediate notification for critical alerts
        if severity == AlertSeverity.CRITICAL:
            self._notify_critical_alert(alert)

    def generate_report(self, report_type: str = 'summary') -> str:
        """Generate security reports"""
        if report_type == 'summary':
            return self._generate_summary_report()
        elif report_type == 'detailed':
            return self._generate_detailed_report()
        else:
            raise ValueError(f"Unknown report type: {report_type}")

    def _generate_summary_report(self) -> str:
        """Generate summary security report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'alert_summary': {
                'total': len(self.alerts_db),
                'by_severity': defaultdict(int),
                'by_category': defaultdict(int)
            },
            'top_sources': self._get_top_sources(),
            'protocol_distribution': dict(self.protocol_stats)
        }
        
        for alert in self.alerts_db:
            report['alert_summary']['by_severity'][alert.severity.value] += 1
            report['alert_summary']['by_category'][alert.category] += 1
        
        return json.dumps(report, indent=2)

    def _get_top_sources(self, limit: int = 10) -> Dict:
        """Get top source IPs by alert count"""
        source_counts = defaultdict(int)
        for alert in self.alerts_db:
            source_counts[alert.source_ip] += 1
        
        return dict(sorted(source_counts.items(), 
                         key=lambda x: x[1], 
                         reverse=True)[:limit])

class SecurityDashboard:
    def __init__(self, monitor):
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title("Network Security Monitoring Dashboard")
        self.root.configure(bg='#2b2b2b')
        self.root.geometry("1200x800")
        self._setup_ui()
        self.root.after(2000, self._update_gui)

    def _setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure grid layout
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # Stats Panel
        stats_frame = self._create_stats_panel(main_frame)
        stats_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        
        # Alerts Panel
        alerts_frame = self._create_alerts_panel(main_frame)
        alerts_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        # Traffic Graph
        graph_frame = self._create_traffic_graph(main_frame)
        graph_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        # Connections Table
        table_frame = self._create_connections_table(main_frame)
        table_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        # Add new UI elements
        self._create_protocol_panel(main_frame)
        self._create_filter_panel(main_frame)
        self._create_packet_details(main_frame)
        self._add_menu()

    def _create_stats_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Network Statistics")
        
        # Stats labels
        self.packets_label = ttk.Label(frame, text="Total Packets: 0")
        self.packets_label.pack(pady=5)
        
        self.ips_label = ttk.Label(frame, text="Unique IPs: 0")
        self.ips_label.pack(pady=5)
        
        self.rate_label = ttk.Label(frame, text="Packets/sec: 0")
        self.rate_label.pack(pady=5)
        
        return frame

    def _create_alerts_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Security Alerts")
        
        # Alerts listbox
        self.alerts_list = tk.Listbox(frame, height=8, bg='#1e1e1e', fg='#ff4444')
        self.alerts_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        return frame

    def _create_traffic_graph(self, parent):
        frame = ttk.LabelFrame(parent, text="Network Traffic")
        
        # Create matplotlib figure
        self.figure = Figure(figsize=(12, 4), facecolor='#2b2b2b')
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor('#1e1e1e')
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.figure, frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initialize plot data
        self.times = []
        self.packet_counts = []
        
        return frame

    def _create_connections_table(self, parent):
        frame = ttk.LabelFrame(parent, text="Recent Connections")
        
        # Create treeview
        columns = ('Time', 'Source IP', 'Destination IP', 'Protocol', 'Length')
        self.tree = ttk.Treeview(frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack elements
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        return frame

    def _create_protocol_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Protocol Analysis")
        
        # Protocol tree
        self.proto_tree = ttk.Treeview(frame, height=10)
        self.proto_tree.pack(fill=tk.BOTH, expand=True)
        
        return frame

    def _create_filter_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Packet Filters")
        
        # Filter entry
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(frame, textvariable=self.filter_var)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Apply button
        apply_btn = ttk.Button(frame, text="Apply Filter", 
                             command=self._apply_filter)
        apply_btn.pack(side=tk.RIGHT)
        
        return frame

    def _create_packet_details(self, parent):
        frame = ttk.LabelFrame(parent, text="Packet Inspector")
        
        # Detail view
        self.detail_text = tk.Text(frame, height=10, bg='#1e1e1e', 
                                 fg='white', font=('Courier', 10))
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        
        return frame

    def _add_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Capture...", 
                            command=self._save_capture)
        file_menu.add_command(label="Load Capture...", 
                            command=self._load_capture)

    def _apply_filter(self):
        filter_str = self.filter_var.get()
        self.monitor.filters = [filter_str] if filter_str else []

    def _save_capture(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("Packet Capture", "*.pcap")]
        )
        if filename:
            self.monitor.save_capture(filename)

    def _load_capture(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Packet Capture", "*.pcap")]
        )
        if filename:
            self.monitor.load_capture(filename)

    def _update_gui(self):
        # Update stats
        total_packets = len(self.monitor.packet_queue)
        unique_ips = len(self.monitor.packet_counts)
        
        self.packets_label.config(text=f"Total Packets: {total_packets}")
        self.ips_label.config(text=f"Unique IPs: {unique_ips}")
        
        # Update alerts
        for alert in self.monitor.stats.get('alerts', []):
            self.alerts_list.insert(0, alert)
            if self.alerts_list.size() > 100:
                self.alerts_list.delete(100)
        
        # Update graph
        current_time = datetime.now()
        self.times.append(current_time)
        self.packet_counts.append(total_packets)
        
        # Keep last 60 seconds of data
        if len(self.times) > 60:
            self.times.pop(0)
            self.packet_counts.pop(0)
        
        self.ax.clear()
        self.ax.plot(self.times, self.packet_counts, 'g-')
        self.ax.set_title('Packet Count Over Time', color='white')
        self.ax.set_xlabel('Time', color='white')
        self.ax.set_ylabel('Packets', color='white')
        self.ax.tick_params(colors='white')
        self.canvas.draw()
        
        # Update table with recent connections
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for packet in list(self.monitor.packet_queue)[-10:]:
            if hasattr(packet, 'time') and packet.haslayer(IP):
                self.tree.insert('', 0, values=(
                    datetime.fromtimestamp(packet.time).strftime('%H:%M:%S'),
                    packet[IP].src,
                    packet[IP].dst,
                    packet[IP].proto,
                    len(packet)
                ))
        
        # Update protocol tree
        for proto, count in self.monitor.protocol_stats.items():
            if not self.proto_tree.exists(proto):
                self.proto_tree.insert('', 'end', iid=proto, 
                                     text=f"{proto}: {count}")
            else:
                self.proto_tree.item(proto, text=f"{proto}: {count}")

        # Update packet details when selected
        selected = self.tree.selection()
        if selected:
            packet = self.monitor.packet_queue[int(selected[0])]
            self.detail_text.delete('1.0', tk.END)
            self.detail_text.insert('1.0', packet.show(dump=True))

        # Schedule next update
        self.root.after(2000, self._update_gui)

    def run(self):
        """Start the dashboard"""
        self.root.mainloop()

def main():
    # Initialize the security monitor
    monitor = SecurityMonitor()
    monitor.start_capture()
    
    # Start the dashboard
    dashboard = SecurityDashboard(monitor)
    dashboard.run()

if __name__ == "__main__":
    main()