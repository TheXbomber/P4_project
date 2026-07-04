import sys
from scapy.all import *
from scapy.contrib.mpls import MPLS
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

# Define standard NSH sub-headers in Scapy
class NSHBase(Packet):
    name = "NSHBase"
    fields_desc = [
        BitField("ver", 0, 2),
        BitField("oam", 0, 1),
        BitField("context", 0, 1),
        BitField("reserved", 0, 6),
        BitField("length", 6, 6),
        ByteField("md_type", 1),
        ByteField("next_proto", 3)
    ]

class NSHSFP(Packet):
    name = "NSHSFP"
    fields_desc = [
        ThreeBytesField("spi", 0),
        ByteField("si", 0)
    ]

class NSHContext(Packet):
    name = "NSHContext"
    fields_desc = [
        IntField("c1", 0),
        IntField("c2", 0),
        IntField("c3", 0),
        IntField("c4", 0)
    ]

def parse_pcap(filepath):
    print(f"Reading capture file: {filepath}\n" + "=" * 80)
    try:
        reader = PcapReader(filepath)
    except Exception as e:
        print(f"Error opening file: {e}")
        return

    count = 0
    for pkt in reader:
        # The reader returns Raw packets on these interfaces because of LinkType.
        # We manually parse the bytes starting from the outer Ethernet frame.
        raw_bytes = bytes(pkt)
        outer_eth = Ether(raw_bytes)
        
        # We check if the outer payload is MPLS (0x8847)
        if outer_eth.type == 0x8847:
            count += 1
            print(f"\n--- PACKET #{count} (MPLS Encapsulated) ---")
            print(f"  [Outer Ethernet] Src: {outer_eth.src} -> Dst: {outer_eth.dst} | Type: MPLS (0x8847)")
            
            # Extract MPLS layer
            mpls_layer = outer_eth.payload
            if isinstance(mpls_layer, MPLS):
                print(f"  [MPLS Header]     Label: {mpls_layer.label} | COS: {mpls_layer.cos} | S: {mpls_layer.s} | TTL: {mpls_layer.ttl}")
                
                # Manually parse NSH Base Header directly from MPLS payload
                nsh_base = NSHBase(bytes(mpls_layer.payload))
                
                # Manually parse NSH Service Path Header
                nsh_sfp = NSHSFP(bytes(nsh_base.payload))
                
                # Manually parse NSH Context Headers
                nsh_ctx = NSHContext(bytes(nsh_sfp.payload))
                
                print(f"  [NSH Base Header] Length: {nsh_base.length} | MD Type: {nsh_base.md_type} | Next Proto: {nsh_base.next_proto}")
                print(f"  [NSH SFP Header]  SPI: {nsh_sfp.spi} | SI: {nsh_sfp.si}")
                
                # Extract Inner Ethernet
                inner_eth = Ether(bytes(nsh_ctx.payload))
                print(f"  [Inner Ethernet]  Src: {inner_eth.src} -> Dst: {inner_eth.dst} | Type: IPv4 (0x0800)")
                
                # Extract Inner IP
                inner_ip = inner_eth.payload
                if isinstance(inner_ip, IP):
                    print(f"  [Inner IPv4]      {inner_ip.src} -> {inner_ip.dst} | DSCP: {inner_ip.tos >> 2}")
                    
                    # Extract Inner TCP
                    inner_tcp = inner_ip.payload
                    if isinstance(inner_tcp, TCP):
                        print(f"  [Inner TCP]       Sport: {inner_tcp.sport} -> Dport: {inner_tcp.dport} | Seq: {inner_tcp.seq} | Flags: {inner_tcp.flags}")
        if count >= 10:
            break

    if count == 0:
        print("No MPLS-encapsulated packets found in this capture.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_captures.py <path_to_pcap>")
    else:
        parse_pcap(sys.argv[1])
