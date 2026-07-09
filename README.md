# P4 project #

## Project Overview & Architecture ##

This project implements a **Service Function Chain (SFC)** architecture in P4. The solution leverages **Network Service Header (NSH)** encapsulation transported over **MPLS tunnels** to dynamically route client-server traffic through a series of network middleboxes (Service Functions) before reaching the destination.

### Key Components

1. **SFC Classifier (Node `b`)**:
   * Inspects incoming client traffic.
   * Matches traffic against configured policies (IP addresses/ports).
   * Encapsulates matching packets by shifting the original Ethernet frame to `inner_ethernet`, prepending a standard 24-byte **NSH Header** and pushing an **MPLS transport label**.
   
2. **Service Function Forwarders (SFFs - Nodes `d` and `e`)**:
   * Parse NSH-encapsulated packets.
   * Forward packets based on the `(SPI, SI)` (Service Path Identifier, Service Index) tuple.
   * **NSH-Unaware Proxy Behavior**: Since the Service Functions (`sf1`, `sf2`, `sf3`) are NSH-unaware:
     * **Outbound**: The SFF strips the MPLS and NSH layers and restores the original Ethernet frame before sending the packet to the Service Function (`Eth / IPv4 / TCP`). The Service Functions implement a simple reflector that simply sends the original packet back.
     * **Inbound (Return)**: When the packet returns from the Service Function, the SFF decodes the SPI from the IP DSCP field (where it was stored as metadata), restores the correct NSH context, decrements the Service Index (`SI = SI - 1`), re-encapsulates it back into the MPLS tunnel, and forwards it to the next SFF.
   * **Chain Completion**: Once the packet completes the service chain (`SI = 1` returning from the last SF), the SFF permanently strips the encapsulation and forwards the packet natively to the destination.

3. **MPLS Core Transit (Switches `a`, `c`, `f`, `g`, `h`)**:
   * Transit switches forward packets between the SFFs using standard MPLS label swap actions, bypassing IP/NSH parsing.

4. **Service Function Chains**:
   * **SFC 13 (h1 $\rightarrow$ h3)**: `h1` $\rightarrow$ `sf1` (on `d`) $\rightarrow$ `sf3` (on `e`) $\rightarrow$ `sf2` (on `d`) $\rightarrow$ `h3`.
   * **SFC 24 (h2 $\rightarrow$ h4)**: `h2` $\rightarrow$ `sf3` (on `e`) $\rightarrow$ `h4`.
   * **Return Traffic**: Bypasses the service chains and follows the shortest path natively over IPv4.

---

## Setup ##
Move to the `src` folder and build the custom image for the service function nodes by running:
```
docker build -f dockerfile.sf -t service_function .
```
Launch the Katharà lab with
```
kathara lstart
```

## Testing ##
Open a server (servers are automatically opened at startup in `h3` and `h4`) with
```
iperf3 -s
```
and a client with
```
iperf3 -c <server_ip> -t <duration>
```
to test.

Setup a capture in the desired device with
```
tcpdump -i <interface> -w /shared/pkt_captures/<filename>.pcap
```
and inspect it in your machine through Wireshark with
```
./inspect_capture.sh <filename>.pcap
```
Make sure to use the `inspect_capture.sh` script to open Wireshark: this allows the program to correctly show the Network Service Header.

## Packet structure ##
### Core transit links (SFF to SFF) ###
```
+-----------------------------------------------------------------------+
|  Outer Ethernet Header                                                |
|    - Dst MAC   : Next Hop Core/SFF Switch MAC                         |
|    - Src MAC   : Current Switch MAC                                   |
|    - EtherType : 0x8847 (MPLS Unicast)                                |
+-----------------------------------------------------------------------+
|  MPLS Shim Header                                                     |
|    - Label     : Core routing label (e.g., 102, 107)                  |
|    - BoS       : 1 (Bottom of Stack)                                  |
+-----------------------------------------------------------------------+
|  NSH Base Header                                                      |
|    - Length    : 6 (indicates 24-byte NSH header length)              |
|    - MD Type   : 1 (Metadata Type 1)                                  |
|    - Next Proto: 3 (Ethernet)                                         |
+-----------------------------------------------------------------------+
|  NSH Service Path Header                                              |
|    - SPI       : Service Path ID (e.g., 13)                           |
|    - SI        : Service Index (e.g., 2)                              |
+-----------------------------------------------------------------------+
|  NSH Context Headers                                                  |
|    - c1, c2, c3, c4 (16 bytes of metadata initialized to 0)           |
+-----------------------------------------------------------------------+
|  Inner Ethernet Header                                                |
|    - Dst MAC   : Final Host MAC / Router Gateway                      |
|    - Src MAC   : Originating Host MAC                                 |
|    - EtherType : 0x0800 (IPv4)                                        |
+-----------------------------------------------------------------------+
|  IPv4 Header (Original payload)                                       |
|    - Src IP    : Client Host IP (e.g., 10.0.1.10)                     |
|    - Dst IP    : Server Host IP (e.g., 10.1.1.10)                     |
+-----------------------------------------------------------------------+
|  TCP Header                                                           |
+-----------------------------------------------------------------------+
|  Payload Data (e.g., iperf3 traffic)                                  |
+-----------------------------------------------------------------------+
```
To automatically decode the NSH header and payload natively in Wireshark, run it with the Lua dissector script:
```
wireshark -X lua_script:shared/nsh_mpls.lua <path_to_pcap>
```

### Service Function links (SFF to SF / SF to SFF) ###

```
+-----------------------------------------------------------------------+
|  Ethernet Header                                                      |
|    - Dst MAC   : Service Function MAC (or SFF MAC on return)          |
|    - Src MAC   : SFF MAC (or Service Function MAC on return)          |
|    - EtherType : 0x0800 (IPv4)                                        |
+-----------------------------------------------------------------------+
|  IPv4 Header (Original payload)                                       |
|    - Src IP    : Client Host IP (e.g., 10.0.1.10)                     |
|    - Dst IP    : Server Host IP (e.g., 10.1.1.10)                     |
+-----------------------------------------------------------------------+
|  TCP Header                                                           |
+-----------------------------------------------------------------------+
|  Payload Data (e.g., iperf3 traffic)                                  |
+-----------------------------------------------------------------------+
```