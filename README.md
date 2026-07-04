# P4 project #

## Setup ##
Custom image for service function nodes must be built by running:
```
docker build -f dockerfile.sf -t service_function .
```
## Testing ##
Open a server with
```
iperf3 -s
```
and a client with
```
iperf3 -c <server_ip> -t <duration>
```
to test.

Setup a capture with
```
tcpdump -i <interface> -w /shared/pkt_captures/<name>.pcap
```
and open the capture with
```
./wireshark.sh <path_to_pcap>
```

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
|    - Next Proto: 3 (Ethernet)                                         | <--- Tells Wireshark Ethernet follows
+-----------------------------------------------------------------------+
|  NSH Service Path Header                                              |
|    - SPI       : Service Path ID (e.g., 13)                           |
|    - SI        : Service Index (e.g., 2)                              |
+-----------------------------------------------------------------------+
|  NSH Context Headers                                                  |
|    - c1, c2, c3, c4 (16 bytes of metadata initialized to 0)            |
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