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


//mudar aqui
header int_pai_t {
    bit<32> Tamanho_Filho;
    bit<32> Quantidade_Filhos;
    bit<8>  next_header;
    bit<8>  Telemetry_Engine_Redirect;
    bit<32>  Packet_Value;
}

header int_filho_t {
    bit<32> switch_id;
    bit<9> port_in;
    bit<9> port_out;
    bit<48> timestamp;
    bit<6> padding;
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
    bit<32> remaining;
    bit<1> isEndhost;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_int_pai {
      packet.extract(hdr.int_pai);
      meta.remaining = hdr.int_pai.Quantidade_Filhos;
      transition parse_int_filho;
    }

    state parse_int_filho {
      packet.extract(hdr.int_filho.next);
      meta.remaining = meta.remaining -1;
      transition select(meta.remaining){
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
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port, bit<1> isEndhost) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.isEndhost = isEndhost;
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

    action add_intfilho(){

        bit<32> var_swid;
        swid.read(var_swid, 0);
        hdr.int_pai.Quantidade_Filhos = hdr.int_pai.Quantidade_Filhos + 1;

        hdr.int_filho[MAX_HOPS-1].setValid();
        hdr.int_filho[MAX_HOPS-1].ID_Switch = var_swid;
        hdr.int_filho[MAX_HOPS-1].Porta_Entrada = standard_metadata.ingress_port;
        hdr.int_filho[MAX_HOPS-1].Porta_Saida = standard_metadata.egress_spec;
        hdr.int_filho[MAX_HOPS-1].Timestamp = standard_metadata.ingress_global_timestamp;
            
        hdr.int_filho[MAX_HOPS-1].padding = 0;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_FILHO_SIZE; //25;

        hdr.int_filho[MAX_HOPS-1].packet_type_ingress = standard_metadata.instance_type;

    }

    apply {
        if (hdr.ipv4.isValid()) {

            ipv4_lpm.apply();
            if(meta.isEndhost==1 && standard_metadata.instance_type==PKT_INSTANCE_TYPE_NORMAL){
                if(hdr.int_pai.isValid() && hdr.int_pai.Telemetry_Engine_Redirect == 0){
                    clone3(CloneType.I2E, 100, {standard_metadata, meta});
                }
            }
            
            if(!hdr.int_pai.isValid()){
                //Adiciona header Pai
                hdr.int_pai.setValid();
                hdr.int_pai.Tamanho_Filho = INT_FILHO_SIZE; //verificar se existe uma forma de extrair o tamanho das structs
                hdr.int_pai.Quantidade_Filhos = 0;
                hdr.int_pai.Telemetry_Engine_Redirect = 0;
                hdr.int_pai.Packet_Value = standard_metadata.instance_type;
                //salva o protocolo que viria apos o ipv4 no next_header do pai e 
                //seta o protocol do ipv4 para int. 
                //O proximo hop vai identificar a existencia do int_pai no parser pelo IP.proto==TYPE_INT.
                hdr.int_pai.next_header = hdr.ipv4.protocol;
                hdr.ipv4.protocol= TYPE_INT;
                hdr.ipv4.totalLen = hdr.ipv4.totalLen + INT_PAI_SIZE; //hdr.int_pai.sizeInBytes(); //9;
            }

            if(hdr.int_pai.Telemetry_Engine_Redirect == 0){
                //Caso nao seja o pacote que esta indo para o telemetry engine, atualiza stats e adiciona filho
                //Ja existe o pai. Atualiza o numero de filhos e insere novo filho.
                add_intfilho();
            }

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action remove_INT_headers(){
      hdr.int_pai.setInvalid();
      hdr.int_filho[0].setInvalid();
      hdr.int_filho[1].setInvalid();
      hdr.int_filho[2].setInvalid();
      hdr.int_filho[3].setInvalid();
      hdr.int_filho[4].setInvalid();
      hdr.int_filho[5].setInvalid();
      hdr.int_filho[6].setInvalid();
      hdr.int_filho[7].setInvalid();
      hdr.int_filho[8].setInvalid();
      hdr.int_filho[9].setInvalid();
    }

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