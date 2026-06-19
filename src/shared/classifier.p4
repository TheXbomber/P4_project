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
        // 1. Shift outer ethernet to inner ethernet
        hdr.inner_ethernet = hdr.ethernet;
        
        // 2. Format NSH
        hdr.nsh.setValid();
        hdr.nsh.ver = 0;
        hdr.nsh.spi = spi;
        hdr.nsh.si = si;
        hdr.nsh.next_proto = 0x3; // Custom value indicating inner Ethernet
        
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
    apply { update_checksum(hdr.ipv4.isValid(), { ... }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16); }
}
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mpls);
        packet.emit(hdr.nsh);
        packet.emit(hdr.inner_ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Model(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main();