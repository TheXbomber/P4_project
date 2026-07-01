import sys
import socket
import struct
import fcntl
import threading
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff, sendp
from scapy.packet import Packet


DSCP_MAX = 63          # DSCP is a 6-bit field (0–63)
IFACES   = ["eth0", "eth1"]

SIOCGIFHWADDR = 0x8927


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


def get_mac(iface: str) -> str:
    """Return the MAC address of a local interface as lowercase colon-hex."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            s.fileno(),
            SIOCGIFHWADDR,
            struct.pack('256s', iface.encode()[:15]),
        )
    finally:
        s.close()
    return ':'.join('%02x' % b for b in info[18:24])


def get_dscp(pkt: Packet) -> int:
    """Extract the 6-bit DSCP value from the IP TOS field."""
    return (pkt[IP].tos >> 2) & DSCP_MAX


def set_dscp(pkt: Packet, dscp: int) -> None:
    """Write a new DSCP value into the IP TOS field, preserving the ECN bits."""
    ecn         = pkt[IP].tos & 0x03           # keep the 2 low ECN bits
    pkt[IP].tos = ((dscp & DSCP_MAX) << 2) | ecn


def process(pkt: Packet, iface: str) -> None:
    # Only handle IPv4 packets with an Ethernet frame
    if not pkt.haslayer(IP) or not pkt.haslayer(Ether):
        return

    old_dscp = get_dscp(pkt)
    new_dscp = (old_dscp + 1) % (DSCP_MAX + 1)   # wrap around at 63 → 0

    set_dscp(pkt, new_dscp)

    # Invalidate checksums — Scapy recomputes them on send
    del pkt[IP].chksum
    if pkt.haslayer(TCP):
        del pkt[TCP].chksum
    if pkt.haslayer(UDP):
        del pkt[UDP].chksum

    print(
        f"[{iface}]  {pkt[IP].src} -> {pkt[IP].dst}"
        f"  DSCP {old_dscp} -> {new_dscp}"
    )

    sendp(pkt, iface=iface, verbose=False)


def sniff_iface(iface: str, own_mac: str) -> None:
    """Run a sniff loop on a single interface, excluding self-sent frames."""
    bpf = f"ip and not ether src {own_mac}"
    print(f"[{iface}] own MAC={own_mac}  filter=\"{bpf}\"")
    sniff(
        iface=iface,
        prn=lambda pkt: process(pkt, iface),
        filter=bpf,        # BPF: IPv4 only, excludes our own transmitted frames
        store=False,
    )


def main() -> None:
    ifaces = get_available_ifaces(IFACES)
    print(f"Listening on: {ifaces}  —  Ctrl+C to stop\n" + "=" * 50)

    own_macs = {}
    for iface in ifaces:
        try:
            own_macs[iface] = get_mac(iface)
        except OSError as e:
            print(f"[ERROR] Could not read MAC for {iface}: {e}")
            sys.exit(1)

    threads = [
        threading.Thread(target=sniff_iface, args=(iface, own_macs[iface]), daemon=True)
        for iface in ifaces
    ]

    for t in threads:
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\nStopping.")


if __name__ == "__main__":
    main()