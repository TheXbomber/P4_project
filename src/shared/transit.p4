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
        transition accept; // Transit nodes do not need to parse NSH or Inner IP!
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    
    action drop() { mark_to_drop(std_meta); }

    action mpls_swap_and_forward(bit<20> next_label, bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.mpls.label = next_label;
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
    }

    action native_ipv4_route(bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table mpls_core_transit {
        key = { hdr.mpls.label: exact; }
        actions = { mpls_swap_and_forward; drop; }
        size = 512;
    }

    table native_ipv4_shortest_path {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { native_ipv4_route; drop; }
        size = 256;
    }

    apply {
        if (hdr.mpls.isValid()) {
            mpls_core_transit.apply(); // Strict forward-path overlay transport
        } else if (hdr.ipv4.isValid()) {
            native_ipv4_shortest_path.apply(); // Return path or baseline edge traffic
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.mpls);
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