from scapy.all import *

TYPE_INT = 0x1212
TYPE_IPV4 = 0x0800

class INT(Packet):
    name = "INT"
    fields_desc = [
        ShortField("tamanho_filho", 0),
        ShortField("quantidade_filho", 0)
    ]
    def mysummary(self):
        return self.sprintf("tamanho_filho=%tamanho_filho%, quantidade_filho=%quantidade_filho%")


bind_layers(Ether, INT, type=TYPE_INT)
bind_layers(INT, IP, pid=TYPE_IPV4)
