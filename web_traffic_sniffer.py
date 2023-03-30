# Import all required functions and classes from the Scapy library
from scapy.all import *

# Define a function to process captured packets
def process_packet(packet):
    # Check if the packet has both TCP and Raw layers
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        # Extract source and destination IP addresses from the IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Extract source and destination ports from the TCP layer
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Check if the source or destination port is 80 (HTTP traffic)
        if src_port == 80 or dst_port == 80:
            # Print the detected HTTP traffic with source and destination IPs and ports
            print("HTTP traffic detected: {}:{} -> {}:{}".format(src_ip, src_port, dst_ip, dst_port))
            
            # Print the payload of the packet (e.g., HTTP headers and content)
            print(packet[Raw].load.decode(errors='ignore'))

# Start capturing packets with the TCP filter and use the process_packet function as the callback
sniff(filter="tcp", prn=process_packet)
