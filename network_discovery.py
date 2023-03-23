from scapy.all import ARP, Ether, srp
import ipaddress

# Set the IP range for your network (example: '172.16.0.0/24')
network_range = '172.16.0.0/24'

# Generate IP addresses within the specified network range
network = ipaddress.IPv4Network(network_range, strict=False)
ip_addresses = [str(ip) for ip in network]

# Function to send ARP requests in smaller chunks
def send_arp_requests(chunk):
    arp_request = ARP(pdst=chunk)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    return srp(arp_request_broadcast, timeout=2, retry=1, verbose=False)

# Print the IP and MAC addresses of responding hosts
print("IP Address\t\tMAC Address")
print("-----------------------------------------")

# Scan the network in chunks of 10 IP addresses
chunk_size = 10
for i in range(0, len(ip_addresses), chunk_size):
    chunk = ip_addresses[i:i + chunk_size]
    answered, _ = send_arp_requests(chunk)
    
    for sent, received in answered:
        print(f"{received.psrc}\t\t{received.hwsrc}")
