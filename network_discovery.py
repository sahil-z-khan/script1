from scapy.all import ARP, Ether, srp
import ipaddress

# Set the IP range for your Class B network (example: '172.16.0.0/16')
network_range = '172.16.0.0/16'

# Generate IP addresses within the specified network range
network = ipaddress.IPv4Network(network_range, strict=False)
ip_addresses = [str(ip) for ip in network]

# Create an ARP request packet
arp_request = ARP(pdst=ip_addresses)
broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
arp_request_broadcast = broadcast / arp_request

# Send the ARP request and collect responses
answered, _ = srp(arp_request_broadcast, timeout=2, retry=1, verbose=False)

# Print the IP and MAC addresses of responding hosts
print("IP Address\t\tMAC Address")
print("-----------------------------------------")
for sent, received in answered:
    print(f"{received.psrc}\t\t{received.hwsrc}")
