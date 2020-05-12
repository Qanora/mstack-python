from header import Protocol
from header import Structure, TypeLen
import logging
from core import util


class FakeHead(Structure):
    _fields_ = [
        (TypeLen.L4, "src_ip_addr"),
        (TypeLen.L4, "dst_ip_addr"),
        (TypeLen.L1, "NULL"),
        (TypeLen.L1, "prot_type"),
        (TypeLen.L2, "length")
    ]

class UdpPacket(Structure):
    _fields_ = [
        (TypeLen.L2, "src_port"),
        (TypeLen.L2, "dst_port"),
        (TypeLen.L2, "length"),
        (TypeLen.L2, "checksum")
    ]

    def log(self, level, status):
        log = getattr(logging, level)
        log("[UDP %s] (%s -> %s)", status, str(self.src_port), str(self.dst_port))


class Udp(Protocol):
    PROT_TYPE = 0x11

    @classmethod
    def recv(cls, ipv4_packet):
        udp_packet = UdpPacket(ipv4_packet.payload)
        udp_packet.log("info", "TAKE")
        from core.sock import SockManager
        remote_info = ipv4_packet.src_ip_addr, udp_packet.src_port
        local_info = ipv4_packet.dst_ip_addr, udp_packet.dst_port
        sock = SockManager.lookup_unidirectional_sock(Udp.PROT_TYPE, remote_info, local_info)

        sock._remote_ip_addr = ipv4_packet.src_ip_addr
        sock._remote_port = udp_packet.src_port

        if sock is None:
            udp_packet.log("error", "NO SOCK")
            return
        sock.enqueue_data(udp_packet.payload)


    @classmethod
    def write(cls, packet, remote_info, local_info):
        dst_ip_addr, dst_port = remote_info
        src_ip_addr, src_port = local_info
        udp_packet = UdpPacket()
        udp_packet.src_port = src_port
        udp_packet.dst_port = dst_port
        udp_packet.payload = packet
        udp_packet.length = len(udp_packet.buffer)

        fake_head = FakeHead()
        fake_head.src_ip_addr = src_ip_addr
        fake_head.dst_ip_addr = dst_ip_addr
        fake_head.prot_type = Udp.PROT_TYPE
        fake_head.length = len(udp_packet.buffer)

        udp_packet.checksum = 0x0000
        udp_packet.checksum = util.checksum(fake_head.buffer + udp_packet.buffer)
        from header.ipv4 import Ipv4, Ipv4Packet
        ip_packet = Ipv4Packet()
        ip_packet.src_ip_addr = src_ip_addr
        ip_packet.dst_ip_addr = dst_ip_addr
        ip_packet.payload = udp_packet.buffer

        Ipv4.write(ip_packet, Udp.PROT_TYPE)


