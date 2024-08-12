/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

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
  bit<32> tamanho_filho;
  bit<32> quantidade_filhos;
  bit<16> prox_header;
}

header int_filho_t {
  bit<32> id_switch;
  bit<9> porta_entrada;
  bit<9> porta_saida;
  bit<48> timestamp;
  bit<6> padding; // 32 + 9 + 9 + 48 + 6 = 104 => 13 bytes
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
  bit<32> filhos_restantes;
}

struct headers {
    ethernet_t   ethernet;
    int_pai_t    int_pai;
    int_filho_t [10] int_filho;
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
        TYPE_INT: parse_int_pai;
        TYPE_IPV4: parse_ipv4;
        default: accept;
      }
    }

    state parse_int_pai {
      packet.extract(hdr.int_pai);
      meta.filhos_restantes = hdr.int_pai.quantidade_filhos;
      transition parse_int_filho;
    }

    state parse_int_filho {
      packet.extract(hdr.int_filho.next);
      meta.filhos_restantes = meta.filhos_restantes -1;
      transition select(meta.filhos_restantes){
        0: parse_ipv4;
        default: parse_int_filho;
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
    
    // Estudar essa parte
    register<bit<32>>(1) swid;


    action drop() {
      mark_to_drop(standard_metadata);
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

    action add_int_filho(){
      bit<32> var_swid;
      swid.read(var_swid, 0);
      hdr.int_pai.quantidade_filhos = hdr.int_pai.quantidade_filhos + 1;

      //comando push_front()
      hdr.int_filho.push_front(1);
      hdr.int_filho[0].setValid();
      hdr.int_filho[0].id_switch = var_swid;
      hdr.int_filho[0].porta_entrada = standard_metadata.ingress_port;
      hdr.int_filho[0].porta_saida = standard_metadata.egress_spec;
      hdr.int_filho[0].timestamp = standard_metadata.ingress_global_timestamp;         
      hdr.int_filho[0].padding = 0;
    }

    apply {
      if(!hdr.int_pai.isValid()){
        hdr.int_pai.setValid();
        hdr.int_pai.tamanho_filho = 13;
        hdr.int_pai.quantidade_filhos = 0;
        hdr.int_pai.prox_header = TYPE_IPV4;
        hdr.ethernet.etherType = TYPE_INT;
        add_int_filho();
      } else {
        add_int_filho();
      }

      if (hdr.ipv4.isValid()) {            
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
    //action remove_INT_headers(){
    //  hdr.int_pai.setInvalid();
    //  hdr.int_filho[0].setInvalid();
    //  hdr.int_filho[1].setInvalid();
    //  hdr.int_filho[2].setInvalid();
    //  hdr.int_filho[3].setInvalid();
    //  hdr.int_filho[4].setInvalid();
    //  hdr.int_filho[5].setInvalid();
    //  hdr.int_filho[6].setInvalid();
    //  hdr.int_filho[7].setInvalid();
    //  hdr.int_filho[8].setInvalid();
    //  hdr.int_filho[9].setInvalid();
    //}

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