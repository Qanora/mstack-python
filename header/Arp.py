from header import Protocol
from header import Structure
from header import TypeLen
import logging
from core import util
from core import netdev
from header.Ethernet import Ethernet


class ArpPacket(Structure):
    _fields_ = [
        (TypeLen.L2, "hard_type"),
        (TypeLen.L2, "prot_type"),
        (TypeLen.L1, "hard_size"),
        (TypeLen.L1, "prot_size"),
        (TypeLen.L2, "op"),
        (TypeLen.L6, "src_mac_addr"),
        (TypeLen.L4, "src_ip_addr"),
        (TypeLen.L6, "dst_mac_addr"),
        (TypeLen.L4, "dst_ip_addr")
    ]

    def LOG(self, level, status):
        log = getattr(logging, level)
        log("[ARP: %s] (%s:%s -> %s:%s), %s", status, util.ip_i2s(self.src_ip_addr),
                     util.mac_i2s(self.src_mac_addr), util.ip_i2s(self.dst_ip_addr),
                     util.mac_i2s(self.dst_mac_addr), hex(self.op))


class Arp(Protocol):
    REQUEST = 0x01
    RESPONSE = 0x02
    PROT_TYPE = 0x0806
    arp_cache = {}

    @classmethod
    def recv(cls, packet):
        arp_packet = ArpPacket(packet)
        arp_packet.LOG("info", "TAKE")
        Arp.arp_cache[arp_packet.src_ip_addr] = arp_packet.src_mac_addr
        if arp_packet.op == Arp.REQUEST:
            arp_packet.LOG("info", "REQUEST")
            reply_packet = ArpPacket()
            reply_packet.op = 0x02
            reply_packet.src_mac_addr = netdev.NetDevManager.get_net_dev_by_ip(arp_packet.dst_ip_addr).mac_addr
            reply_packet.dst_mac_addr = arp_packet.src_mac_addr
            reply_packet.dst_ip_addr = arp_packet.src_ip_addr
            reply_packet.src_ip_addr = arp_packet.dst_ip_addr
            reply_packet.hard_type = 0x0001
            reply_packet.prot_type = 0x0800
            reply_packet.hard_size = 0x06
            reply_packet.prot_size = 0x04
            reply_packet.LOG("info", "OUT")
            Ethernet.write(reply_packet, Arp.PROT_TYPE)
        elif arp_packet.op == Arp.RESPONSE:
            arp_packet.LOG("info", "RESPONSE")
        else:
            arp_packet.LOG("error", "UNSUPPORT")


    @classmethod
    def query(cls, ip_addr):
        if ip_addr in Arp.arp_cache:
            return Arp.arp_cache[ip_addr]
        return None

    @classmethod
    def write(cls, packet, info):
        pass
