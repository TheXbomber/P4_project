from scapy.all import *

iface = "eth0"
my_mac = get_if_hwaddr(iface)

def reflect(pkt):
    if Ether in pkt:
        # swap MACs, leave everything else (IP header + payload) untouched
        pkt[Ether].src, pkt[Ether].dst = my_mac, pkt[Ether].src
        sendp(pkt, iface=iface, verbose=False)

# only capture frames actually destined to B's own MAC,
# so we don't re-capture the frames we just sent back out (loop prevention)
sniff(iface=iface, filter=f"ether dst {my_mac}", prn=reflect, store=False)