from scapy.all import *

def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        if src_port == 80 or dst_port == 80:
            print(f"HTTP traffic detected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            print(packet[Raw].load.decode(errors='ignore'))

sniff(filter="tcp", prn=process_packet)
