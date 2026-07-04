#include "headers.p4"

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x8847: parse_mpls;
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_mpls {
        packet.extract(hdr.mpls);
        transition select(hdr.mpls.bos) {
            1: parse_nsh_ethernet;
            default: accept;
        }
    }
    state parse_nsh_ethernet {
        packet.extract(hdr.nsh_ethernet);
        transition select(hdr.nsh_ethernet.etherType) {
            0x894F: parse_nsh_base;
            default: accept;
        }
    }
    state parse_nsh_base {
        packet.extract(hdr.nsh_base);
        transition select(hdr.nsh_base.next_proto) {
            default: parse_nsh_sfp;
        }
    }
    state parse_nsh_sfp {
        packet.extract(hdr.nsh_sfp);
        transition select(hdr.nsh_base.md_type) {
            0x01: parse_nsh_context;
            default: parse_ipv4;
        }
    }
    state parse_nsh_context {
        packet.extract(hdr.nsh_context);
        transition parse_ipv4;
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {

    action drop() { mark_to_drop(std_meta); }

    action proxy_to_sf(bit<9> egress_port, bit<48> sf_mac) {
        // Save context into metadata BEFORE stripping
        meta.spi = hdr.nsh_sfp.spi;
        meta.si  = hdr.nsh_sfp.si;

        // Encode SPI into DSCP (upper 6 bits of diffserv) as SPI - 1
        hdr.ipv4.diffserv = (bit<8>)(((bit<8>)(hdr.nsh_sfp.spi - 1) << 2) | (hdr.ipv4.diffserv & 3));

        hdr.mpls.setInvalid();
        hdr.nsh_ethernet.setInvalid();
        hdr.nsh_base.setInvalid();
        hdr.nsh_sfp.setInvalid();
        hdr.nsh_context.setInvalid();
        
        // Rewrite the outer ethernet to become the native IP interface to the SF
        hdr.ethernet.etherType = 0x0800; // IPv4
        hdr.ethernet.dstAddr   = sf_mac;
        std_meta.egress_spec   = egress_port;
    }

    action proxy_return_to_core(bit<24> spi, bit<8> next_si, bit<20> next_mpls, bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.nsh_ethernet.setValid();
        hdr.nsh_ethernet.srcAddr = 0x111111111111;
        hdr.nsh_ethernet.dstAddr = 0x222222222222;
        hdr.nsh_ethernet.etherType = 0x894F; // NSH EtherType

        hdr.nsh_base.setValid();
        hdr.nsh_base.ver        = 0;
        hdr.nsh_base.oam        = 0;
        hdr.nsh_base.context    = 0;
        hdr.nsh_base.reserved   = 0;
        hdr.nsh_base.length     = 0x6;  // 6 words = 24 bytes total
        hdr.nsh_base.md_type    = 0x1;  // MD Type 1
        hdr.nsh_base.next_proto = 0x1;  // Direct IPv4 payload

        hdr.nsh_sfp.setValid();
        hdr.nsh_sfp.spi         = spi;
        hdr.nsh_sfp.si          = next_si;

        hdr.nsh_context.setValid();
        hdr.nsh_context.c1      = 0;
        hdr.nsh_context.c2      = 0;
        hdr.nsh_context.c3      = 0;
        hdr.nsh_context.c4      = 0;

        hdr.mpls.setValid();
        hdr.mpls.label = next_mpls;
        hdr.mpls.bos   = 1;
        hdr.mpls.ttl   = 64;

        hdr.ethernet.etherType = 0x8847;
        hdr.ethernet.dstAddr   = next_hop_mac;
        std_meta.egress_spec   = egress_port;
    }

    action sf_final_forward(bit<9> egress_port, bit<48> next_hop_mac) {        
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action end_of_chain_routing(bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.mpls.setInvalid();
        hdr.nsh_ethernet.setInvalid();
        hdr.nsh_base.setInvalid();
        hdr.nsh_sfp.setInvalid();
        hdr.nsh_context.setInvalid();
        
        // Strip encapsulation and route as native IP packet
        hdr.ethernet.etherType = 0x0800; // IPv4
        hdr.ethernet.dstAddr   = next_hop_mac;
        std_meta.egress_spec   = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv4_forward(bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table sff_nsh_forwarding {
        key = {
            hdr.nsh_sfp.spi: exact;
            hdr.nsh_sfp.si:  exact;
        }
        actions = { proxy_to_sf; end_of_chain_routing; drop; }
        size = 256;
    }

    // Key now includes meta.spi to disambiguate chains sharing the same SF port
    table sf_return_proxy {
        key = {
            std_meta.ingress_port: exact;
            meta.spi:              exact;
        }
        actions = { proxy_return_to_core; sf_final_forward; drop; }
        size = 16;
    }

    table native_ipv4_shortest_path {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; }
        size = 256;
    }

    apply {
        if (hdr.mpls.isValid() && hdr.nsh_base.isValid()) {
            sff_nsh_forwarding.apply();
        } else if (!hdr.mpls.isValid() && !hdr.nsh_base.isValid() && hdr.ipv4.isValid()) {
            // Decode SPI from DSCP (upper 6 bits of diffserv)
            meta.spi = (bit<24>)(hdr.ipv4.diffserv >> 2) + 1;
            if (sf_return_proxy.apply().miss) {
                native_ipv4_shortest_path.apply();
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), {
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr
        }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mpls);
        packet.emit(hdr.nsh_ethernet);
        packet.emit(hdr.nsh_base);
        packet.emit(hdr.nsh_sfp);
        packet.emit(hdr.nsh_context);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;