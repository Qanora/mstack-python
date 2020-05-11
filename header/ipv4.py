from header import Protocol
from header import TypeLen
from header import Structure
from header.Ethernet import Ethernet
from header.icmp import Icmp
from header.udp import Udp
from header.tcp import Tcp
import logging
from core import util


class Ipv4Packet(Structure):
    _fields_ = [
        (TypeLen.L1, "version_ihl"),
        (TypeLen.L1, "type_of_service"),
        (TypeLen.L2, "total_length"),
        (TypeLen.L2, "id"),
        (TypeLen.L2, "frag_offset"),
        (TypeLen.L1, "ttl"),
        (TypeLen.L1, "prot_type"),
        (TypeLen.L2, "header_checksum"),
        (TypeLen.L4, "src_ip_addr"),
        (TypeLen.L4, "dst_ip_addr")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        setattr(self, "version", self.version_ihl >> 4)
        setattr(self, "ihl", (self.version_ihl & ((1 << 4) - 1)))
        if bytedata is not None:
            self.header = self._buffer[:self.ihl*4]
            self.payload = self._buffer[self.ihl*4:]

    def flush_version_ihl(self):
        self.version_ihl = (self.version << 4) | (self.ihl)

    def LOG(self, level, status):
        log_format = "[IPV4: %s] (%s -> %s) %s"
        log = getattr(logging, level)
        log(log_format, status, util.ip_i2s(self.src_ip_addr), util.ip_i2s(self.dst_ip_addr), hex(self.prot_type))


class Ipv4(Protocol):
    PROT_TYPE = 0x0800
    id = 0
    log_format = "[IPV4: %s] (%s -> %s) %s"

    @classmethod
    def recv(cls, packet):
        ipv4_packet = Ipv4Packet(packet)
        ipv4_packet.LOG("info", "TAKE")
        if ipv4_packet.prot_type == Icmp.PROT_Type:
            Icmp.recv(ipv4_packet)
        elif ipv4_packet.prot_type == Udp.PROT_TYPE:
            Udp.recv(ipv4_packet)
        elif ipv4_packet.prot_type == Tcp.PROT_TYPE:
            Tcp.recv(packet.payload)
        else:
            ipv4_packet.LOG("error", "UNSUPPORT")

    @classmethod
    def write(cls, ipv4_packet, prot_type):
        if prot_type == Icmp.PROT_Type:

            ipv4_packet.id = Ipv4.id
            Ipv4.id += 1

            ipv4_packet.total_length = len(ipv4_packet.buffer)
            ipv4_packet.header_checksum = 0x0000
            ipv4_packet.header_checksum = util.checksum(ipv4_packet.header)
            Ethernet.write(ipv4_packet, Ipv4.PROT_TYPE)

        if prot_type == Udp.PROT_TYPE:
            ipv4_packet.prot_type = Udp.PROT_TYPE
            ipv4_packet.id = Ipv4.id
            Ipv4.id += 1

            ipv4_packet.version_ihl = 0x45
            ipv4_packet.type_of_service = 0x00
            ipv4_packet.total_length = len(ipv4_packet.buffer)
            ipv4_packet.frag_offset = 0x0000
            ipv4_packet.ttl = 0x40
            ipv4_packet.header_checksum = 0x0000
            ipv4_packet.header_checksum = util.checksum(ipv4_packet.header)
            Ethernet.write(ipv4_packet, Ipv4.PROT_TYPE)