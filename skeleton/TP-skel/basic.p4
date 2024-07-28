/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//TESTE SHARED FOLDER

const bit<16> TYPE_INT  = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header int_pai_t {
    bit<32>   tamanho_filho;
    bit<32>   quantidade_filho;
}

header int_filho_t {
    bit<32>   id_switch;
    bit<9>    porta_entrada;
    bit<9>    porta_saida;
    bit<48>   timestamp;
    bit<1>    ultimo;
    bit<5>    padding;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    int_pai_t    int_pai;
    int_filho_t[10]  int_filho;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT: parse_int;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_int {
        packet.extract(hdr.int_pai);
        packet.extract(hdr.int_filho.next);
        transition select(hdr.int_filho.last.ultimo) {
            1: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action int_add_pai() {
        hdr.int_pai.quantidade_filho = 0;
        hdr.int_pai.setValid();
    }

    action int_add_filho() {
        hdr.int_pai.quantidade_filho = hdr.int_pai.quantidade_filho + 1;
        //hdr.int_filho.id_switch = ;
        //hdr.int_filho.porta_entrada = ;
        //hdr.int_filho.porta_saida = ;
        //hdr.int_filho.timestamp = ;
        //hdr.int_filho.ultimo = 1;
        //hdr.int_filho.padding = 0;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    table int_pai_nao_existe {
        key = {
            hdr.int_pai.quantidade_filho : exact;
        }
        actions = {
            int_add_pai;
        }
        size = 1;
    }

    table int_pai_existe {
        key = {
            hdr.int_pai.quantidade_filho : exact;
        }
        actions = {
            int_add_filho;
        }
        size = 32;
    }

    apply {
        if(hdr.int_pai.isValid()) {
            int_pai_existe.apply();
        } else {
            int_pai_nao_existe.apply();
            int_pai_existe.apply();
        }

        if(hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_pai);
        packet.emit(hdr.int_filho);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
