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

header nsh_base_t {
    bit<2>  ver;
    bit<1>  oam;
    bit<1>  context;     // Unused/Reserved bit
    bit<6>  reserved;    // Reserved bits
    bit<6>  length;      // Length of NSH header in 4-byte words (6 for MD Type 1)
    bit<8>  md_type;     // Metadata Type (1 for MD Type 1)
    bit<8>  next_proto;  // Next Protocol (3 for Ethernet)
}

header nsh_sfp_t {
    bit<24> spi;         // Service Path Identifier
    bit<8>  si;          // Service Index
}

header nsh_context_t {
    bit<32> c1;          // Mandatory Context Header 1
    bit<32> c2;          // Mandatory Context Header 2
    bit<32> c3;          // Mandatory Context Header 3
    bit<32> c4;          // Mandatory Context Header 4
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
    ethernet_t    ethernet;
    mpls_t        mpls;
    ethernet_t    nsh_ethernet;   // Intermediate Ethernet wrapper for NSH (etherType = 0x894F)
    nsh_base_t    nsh_base;
    nsh_sfp_t     nsh_sfp;
    nsh_context_t nsh_context;
    ipv4_t        ipv4;
}

struct metadata {
    bit<24> spi;
    bit<8>  si;
}

#endif