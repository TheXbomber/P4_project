#ifndef _HEADERS_P4_
#define _HEADERS_P4_

#include <core.p4>
#include <v1model.p4>

// Standard Ethernet Header
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

// MPLS Header (Shim Layer)
header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  bos; // Bottom of Stack flag
    bit<8>  ttl;
}

// Network Service Header (NSH) - RFC 8300 compliant base header (8 bytes)
header nsh_t {
    bit<2>  ver;
    bit<1>  oam;
    bit<1>  reserved1;   // "U" bit - unused, must be 0
    bit<6>  ttl;
    bit<6>  length;      // total NSH length in 4-byte words
    bit<4>  reserved2;   // "UUUU" - unused, must be 0
    bit<4>  md_type;     // 0x2 = variable-length context (0 context headers here)
    bit<8>  next_proto;  // IANA: 0x1=IPv4, 0x2=IPv6, 0x3=Ethernet, 0x4=NSH, 0x5=MPLS
    bit<24> spi;         // Service Path Identifier
    bit<8>  si;          // Service Index
}

// Standard IPv4 Header
header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  totalLen;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  fragOffset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdrChecksum;
    bit<32>  srcAddr;
    bit<32>  dstAddr;
}

struct headers {
    ethernet_t ethernet;
    mpls_t     mpls;
    nsh_t      nsh;
    ethernet_t inner_ethernet; // For Eth/MPLS/NSH/Eth/IPv4 encapsulation
    ipv4_t     ipv4;
}

struct metadata {
    bit<24> spi;
    bit<8>  si;
}

#endif
