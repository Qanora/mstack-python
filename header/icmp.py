from header import Protocol
from header import Structure
from header import TypeLen
import logging
from core import util


class IcmpPacket(Structure):
    _fields_ = [
        (TypeLen.L1, "prot_type"),
        (TypeLen.L1, "code"),
        (TypeLen.L2, "checksum"),
        (TypeLen.L2, "id"),
        (TypeLen.L2, "seq")
    ]

    def LOG(self, level, status):
        log = getattr(logging, level)
        log("[ICMP: %s], %s", status, hex(self.prot_type))

class Icmp(Protocol):
    PROT_Type = 0x01

    @classmethod
    def recv(cls, ipv4_packet):
        packet = ipv4_packet.payload
        icmp_packet = IcmpPacket(packet)
        icmp_packet.LOG("info", "TAKE")
        if icmp_packet.prot_type == 0x08:
            reply_packet = IcmpPacket()
            reply_packet.prot_type = 0x00
            reply_packet.seq = icmp_packet.seq
            reply_packet.code = 0x00
            reply_packet.id = icmp_packet.id
            reply_packet.payload = icmp_packet.payload
            reply_packet.checksum = util.checksum(reply_packet.buffer)
            ipv4_packet.payload = reply_packet.buffer

            src_ip_addr = ipv4_packet.src_ip_addr
            ipv4_packet.src_ip_addr = ipv4_packet.dst_ip_addr
            ipv4_packet.dst_ip_addr = src_ip_addr
            from header.ipv4 import Ipv4
            Ipv4.write(ipv4_packet, Icmp.PROT_Type)



        else:
            icmp_packet.LOG("error", "UNSUPPORT")
