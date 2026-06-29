
import sys
import socket
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp
from scapy.packet import Packet


DSCP_MAX = 63          # DSCP is a 6-bit field (0–63)
IFACES   = ["eth0", "eth1"]


def get_available_ifaces(candidates: list[str]) -> list[str]:
    """Return only the interfaces that actually exist on this machine."""
    try:
        available = socket.if_nameindex()           # [(index, name), ...]
        names     = {name for _, name in available}
    except OSError:
        names = set()

    found = [iface for iface in candidates if iface in names]

    if not found:
        print(f"[ERROR] None of {candidates} found. Exiting.")
        sys.exit(1)

    for iface in candidates:
        if iface not in names:
            print(f"[WARN]  {iface} not found, skipping.")

    return found


def get_dscp(pkt: Packet) -> int:
    """Extract the 6-bit DSCP value from the IP TOS field."""
    # TOS byte = [ DSCP (6 bits) | ECN (2 bits) ]
    return (pkt[IP].tos >> 2) & DSCP_MAX


def set_dscp(pkt: Packet, dscp: int) -> None:
    """Write a new DSCP value into the IP TOS field, preserving the ECN bits."""
    ecn         = pkt[IP].tos & 0x03           # keep the 2 low ECN bits
    pkt[IP].tos = ((dscp & DSCP_MAX) << 2) | ecn


def process(pkt: Packet) -> None:
    # Only handle IPv4 packets with an Ethernet frame
    if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
        return

    iface    = pkt.sniffed_on
    old_dscp = get_dscp(pkt)
    new_dscp = (old_dscp + 1) % (DSCP_MAX + 1)   # wrap around at 63 → 0

    set_dscp(pkt, new_dscp)

    # Invalidate checksums — Scapy recomputes them on send
    del pkt[IP].chksum
    if pkt.haslayer("TCP"):
        from scapy.layers.inet import TCP
        del pkt[TCP].chksum
    if pkt.haslayer("UDP"):
        from scapy.layers.inet import UDP
        del pkt[UDP].chksum

    print(
        f"[{iface}]  {pkt[IP].src} → {pkt[IP].dst}"
        f"  DSCP {old_dscp} → {new_dscp}"
    )

    sendp(pkt, iface=iface, verbose=False)


def main() -> None:
    ifaces = get_available_ifaces(IFACES)
    print(f"Listening on: {ifaces}  —  Ctrl+C to stop\n" + "=" * 50)

    sniff(
        iface=ifaces,
        prn=process,
        filter="ip",       # BPF: IPv4 only, kernel-level for performance
        store=False,
    )


if __name__ == "__main__":
    main()