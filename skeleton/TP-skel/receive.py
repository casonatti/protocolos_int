#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    Packet,
    Ether,
    IP,
    TCP,
    BitField,
    ShortField,
    IntField,
    PacketListField,
    IPOption,
    bind_layers,
    get_if_list,
    sniff
)

from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# class IPOption_MRI(IPOption):
#     name = "MRI"
#     option = 31
#     fields_desc = [ _IPOption_HDR,
#                     FieldLenField("length", None, fmt="B",
#                                   length_of="swids",
#                                   adjust=lambda pkt,l:l+4),
#                     ShortField("count", 0),
#                     FieldListField("swids",
#                                    [],
#                                    IntField("", 0),
#                                    length_from=lambda pkt:pkt.count*4) ]

class INT_Filho(Packet):
    name = "INT Filho"
    fields_desc = [  BitField("id_switch",0, 32),
                     BitField("porta_entrada",0, 9),
                     BitField("porta_saida",0, 9),
                     BitField("timeStamp",0, 48),
                     BitField("padding",0, 6),
                    ]

class INT(Packet):
    name = "INT packet"

    fields_desc=[ BitField("tamanho_filho", 0, 32),
                  BitField("quantidade_filhos", None, 32),
                  BitField("prox_header", 0, 16),
                  PacketListField("plist", None, INT_Filho, count_from= lambda pkt:pkt.quantidade_filhos)]


# def handle_pkt(pkt):
#     if INT in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
#         print("got a packet")
#         pkt.show2()
#     #    hexdump(pkt)
#         sys.stdout.flush()
#     pkt.show2()

def handle_pkt(pkt):
    
    # if TCP in pkt and pkt[TCP].dport == 1234:
    # if INT in pkt and pkt[INT].prox_header != 1:
    # if pkt[INT].prox_header != 0:
    print("got a packet")
    pkt.show2()

    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    bind_layers(Ether, INT, Type = 0x1212)
    bind_layers(INT, INT_Filho)
    bind_layers(INT_Filho, IP)

    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
