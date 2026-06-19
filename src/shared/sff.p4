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
        // If bottom-of-stack is true, parse NSH next
        transition select(hdr.mpls.bos) {
            1: parse_nsh;
            default: accept; 
        }
    }
    state parse_nsh {
        packet.extract(hdr.nsh);
        packet.extract(hdr.inner_ethernet);
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

    // Action 1: Strip overlay and route bare packet to the local Service Function
    action proxy_to_sf(bit<9> egress_port, bit<48> sf_mac) {
        hdr.mpls.setInvalid();
        hdr.nsh.setInvalid();
        hdr.ethernet = hdr.inner_ethernet; // Restore original host ethernet frame
        hdr.ethernet.dstAddr = sf_mac;
        std_meta.egress_spec = egress_port;
    }

    // Action 2: Process return packet from SF, restore context, decrement SI, forward to next remote SFF
    action proxy_return_to_core(bit<24> spi, bit<8> next_si, bit<20> next_mpls, bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.inner_ethernet = hdr.ethernet;
        
        hdr.nsh.setValid();
        hdr.nsh.spi = spi;
        hdr.nsh.si = next_si; // Decremented Service Index
        
        hdr.mpls.setValid();
        hdr.mpls.label = next_mpls;
        hdr.mpls.bos = 1;
        
        hdr.ethernet.etherType = 0x8847;
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
    }

    // Action 3: Final chain hop completed. Strip everything and send to destination via plain IPv4
    action end_of_chain_routing(bit<9> egress_port, bit<48> next_hop_mac) {
        hdr.mpls.setInvalid();
        hdr.nsh.setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ethernet.dstAddr = next_hop_mac;
        std_meta.egress_spec = egress_port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table sff_nsh_forwarding {
        key = {
            hdr.nsh.spi: exact;
            hdr.nsh.si: exact;
        }
        actions = { proxy_to_sf; end_of_chain_routing; drop; }
        size = 256;
    }

    table sf_return_proxy {
        key = {
            std_meta.ingress_port: exact; // Identify which SF it came from based on ingress port
        }
        actions = { proxy_return_to_core; drop; }
        size = 16;
    }

    // Traditional lookup used exclusively for return traffic path bypass
    table native_ipv4_shortest_path {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ... }
    }

    apply {
        if (hdr.mpls.isValid() && hdr.nsh.isValid()) {
            sff_nsh_forwarding.apply();
        } else if (!hdr.mpls.isValid() && !hdr.nsh.isValid() && hdr.ipv4.isValid()) {
            // Determine if it's an un-encapsulated packet returning from a local SF
            if (sf_return_proxy.apply().miss) {
                // If it wasn't an SF, it must be plain return traffic bypassing SFC
                native_ipv4_shortest_path.apply();
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }
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