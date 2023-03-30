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
            
            # Decode the raw payload and store it in the 'payload' variable
            payload = packet[Raw].load.decode(errors='ignore')
            # Print the decoded payload (e.g., HTTP headers and content)
            print(payload)

            # Initialize a list to store possible credentials found in the payload
            possible_credentials = []
            # Loop through common keywords for credentials
            for keyword in ["username", "password", "user", "pass", "login"]:
                # Check if the keyword is present in the payload (case-insensitive)
                if keyword in payload.lower():
                    # Add the keyword to the list of possible credentials
                    possible_credentials.append(keyword)

            # If any possible credentials were found, print a message with the detected keywords
            if possible_credentials:
                print(f"Possible credentials detected: {', '.join(possible_credentials)}")

# Start capturing packets with the TCP filter and use the process_packet function as the callback
sniff(filter="tcp", prn=process_packet)
