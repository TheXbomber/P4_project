#include "headers.p4"

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    
    action drop() {
        mark_to_drop(std_meta);
    }
    
    // Action to classify and onboard a packet into an SFC chain
    action sfc_encapsulate(bit<24> spi, bit<8> si, bit<20> mpls_label, bit<9> egress_port, bit<48> next_hop_mac) {
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
        hdr.nsh_sfp.si          = si;

        hdr.nsh_context.setValid();
        hdr.nsh_context.c1      = 0;
        hdr.nsh_context.c2      = 0;
        hdr.nsh_context.c3      = 0;
        hdr.nsh_context.c4      = 0;
        
        // 3. Format MPLS
        hdr.mpls.setValid();
        hdr.mpls.label = mpls_label;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 64;
        
        // 4. Update Outer Ethernet for transport
        hdr.ethernet.etherType = 0x8847; // MPLS EtherType
        hdr.ethernet.dstAddr = next_hop_mac;
        
        std_meta.egress_spec = egress_port;
    }

    action ipv4_forward(bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table sfc_classification {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.ipv4.protocol: exact;
        }
        actions = { sfc_encapsulate; ipv4_forward; drop; }
        size = 256;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            sfc_classification.apply();
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { update_checksum(hdr.ipv4.isValid(), {
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
              hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16); }
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