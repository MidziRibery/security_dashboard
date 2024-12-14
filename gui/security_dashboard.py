import tkinter as tk
from tkinter import ttk, filedialog
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime

class SecurityDashboard:
    def __init__(self, monitor):
        self.monitor = monitor
        self.root = tk.Tk()
        self.root.title("Network Security Monitoring Dashboard")
        self.root.geometry("1200x800")
        self._setup_ui()
        self.root.after(2000, self._update_gui)  # Periodic GUI updates

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

    def _create_stats_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Network Statistics")
        self.packets_label = ttk.Label(frame, text="Total Packets: 0")
        self.packets_label.pack(pady=5)
        self.ips_label = ttk.Label(frame, text="Unique IPs: 0")
        self.ips_label.pack(pady=5)
        self.rate_label = ttk.Label(frame, text="Packets/sec: 0")
        self.rate_label.pack(pady=5)
        return frame

    def _create_alerts_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Security Alerts")
        self.alerts_list = tk.Listbox(frame, height=8, bg="#f8f8f8")
        self.alerts_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        return frame

    def _create_traffic_graph(self, parent):
        frame = ttk.LabelFrame(parent, text="Network Traffic")
        self.figure = Figure(figsize=(12, 4), facecolor='white')
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title('Packet Traffic Over Time')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packet Count')
        self.times = []
        self.packet_counts = []
        self.canvas = FigureCanvasTkAgg(self.figure, frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        return frame

    def _create_connections_table(self, parent):
        frame = ttk.LabelFrame(parent, text="Recent Connections")
        columns = ('Time', 'Source IP', 'Destination IP', 'Protocol', 'Size')
        self.tree = ttk.Treeview(frame, columns=columns, show='headings', height=10)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        return frame

    def _update_gui(self):
        # Update stats
        total_packets = len(self.monitor.packet_queue)
        unique_ips = len(self.monitor.packet_counts)
        self.packets_label.config(text=f"Total Packets: {total_packets}")
        self.ips_label.config(text=f"Unique IPs: {unique_ips}")

        # Update alerts
        self.alerts_list.delete(0, tk.END)
        for alert in self.monitor.stats.get('alerts', []):
            self.alerts_list.insert(tk.END, alert)

        # Update graph
        self.times.append(datetime.now())
        self.packet_counts.append(total_packets)
        if len(self.times) > 60:
            self.times.pop(0)
            self.packet_counts.pop(0)
        self.ax.clear()
        self.ax.plot(self.times, self.packet_counts, 'b-')
        self.ax.set_title('Packet Traffic Over Time')
        self.ax.set_xlabel('Time')
        self.ax.set_ylabel('Packet Count')
        self.canvas.draw()

        # Update connections table
        for item in self.tree.get_children():
            self.tree.delete(item)
        for packet in list(self.monitor.packet_queue)[-10:]:
            self.tree.insert('', 'end', values=(
                datetime.fromtimestamp(packet['timestamp']).strftime('%H:%M:%S'),
                packet['src'],
                packet['dst'],
                packet['protocol'],
                packet['size']
            ))

        # Schedule the next update
        self.root.after(2000, self._update_gui)

    def run(self):
        """Start the dashboard"""
        self.root.mainloop()
