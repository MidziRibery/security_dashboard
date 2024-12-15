from scapy.all import *
import time

def create_ddos_pcap():
    """Create a PCAP file simulating a DDoS attack (SYN flood)"""
    packets = []
    target_ip = "192.168.1.100"  # Example target IP
    
    print("Generating DDoS attack packets...")
    
    # Generate SYN flood packets
    for _ in range(1000):  # Generate 1000 packets
        # Create SYN packet from random source IPs
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        syn_packet = IP(src=src_ip, dst=target_ip)/\
                    TCP(sport=RandShort(), dport=80, flags="S")
        packets.append(syn_packet)
    
    # Save to pcap file
    wrpcap("sample_data/ddos_attack.pcap", packets)
    print(f"Saved {len(packets)} DDoS attack packets to sample_data/ddos_attack.pcap")

if __name__ == "__main__":
    create_ddos_pcap()
