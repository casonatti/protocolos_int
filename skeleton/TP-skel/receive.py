#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    Packet,
    TCP,
    FieldLenField,
    FieldListField,
    BitField,
    ByteField,
    IntField,
    PacketListField,
    IPOption,
    ShortField,
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
    fields_desc = [  IntField("ID_Switch",0),
                     BitField("Porta_Entrada",0, 9),
                     BitField("Porta_Saida",0, 9),
                     BitField("TimeStamp",0, 48),
                     BitField("Padding",0, 6),
                    ]

class INT(Packet):
    name = "INT packet"

    fields_desc=[ IntField("Tamanho_Filho",0),
                  IntField("Quantidade_Filhos", None),
                  ByteField("next_header", 6),
                  PacketListField("plist", None, INT_Filho, count_from= lambda pkt:pkt.Quantidade_Filhos)]


# def handle_pkt(pkt):
#     if INT in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
#         print("got a packet")
#         pkt.show2()
#     #    hexdump(pkt)
#         sys.stdout.flush()
#     pkt.show2()

def handle_pkt(pkt):
    
    #if IP in pkt and pkt[IP].proto == 150:
    if INT in pkt and pkt[INT].next_header!= 1:
      print("got a packet")
      pkt.show2()
      
    sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
