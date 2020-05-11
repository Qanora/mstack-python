from header import Structure
from header import TypeLen
import logging
from core import util as u
from header import Protocol


class EthernetPacket(Structure):
    _fields_ = [
        (TypeLen.L6, "dst_mac_addr"),
        (TypeLen.L6, "src_mac_addr"),
        (TypeLen.L2, "prot_type")
    ]

    def LOG(self, level, status):
        log_format = "[Ethernet: %s] (%s -> %s) %s %s"
        log = getattr(logging, level)
        log(log_format, status, u.mac_i2s(self.dst_mac_addr),
            u.mac_i2s(self.src_mac_addr), hex(self.prot_type), len(self.buffer))


class Ethernet(Protocol):

    @classmethod
    def recv(cls, packet):
        e_packet = EthernetPacket(packet)
        e_packet.LOG("info", "TAKE")
        from header.Arp import Arp
        from header.ipv4 import Ipv4
        if e_packet.prot_type == Arp.PROT_TYPE:
            Arp.recv(e_packet.payload)
        elif e_packet.prot_type == Ipv4.PROT_TYPE:
            Ipv4.recv(e_packet.payload)
        else:
            e_packet.LOG("error", "UNSUPPORT")

    @classmethod
    def write(cls, packet, prot_type):
        e_packet = EthernetPacket()
        from header.Arp import Arp
        from header.ipv4 import Ipv4
        from core.netdev import NetDevManager
        if prot_type == Arp.PROT_TYPE:
            arp_packet = packet
            e_packet.dst_mac_addr = arp_packet.dst_mac_addr
            e_packet.src_mac_addr = arp_packet.src_mac_addr
            e_packet.prot_type = prot_type
            e_packet.payload = arp_packet.buffer
        if prot_type == Ipv4.PROT_TYPE:
            ipv4_packet = packet
            e_packet.src_mac_addr = NetDevManager.get_net_dev_by_ip(ipv4_packet.src_ip_addr).mac_addr
            e_packet.dst_mac_addr = Arp.query(ipv4_packet.dst_ip_addr)
            e_packet.prot_type = prot_type
            e_packet.payload = ipv4_packet.buffer
        e_packet.LOG("info", "OUT")
        NetDevManager.get_net_dev_by_ip(packet.src_ip_addr).transmit(e_packet.buffer)
