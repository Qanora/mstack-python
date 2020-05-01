from demux.udpdev import UdpDev
from stack.metapacket import MetaPacket
from demux.portmanager import PortManager
import asyncio
import logging


class UdpPacketField:
    def __init__(self):
        self.attr = {
            'src_port': (0, 2),
            'dst_port': (2, 4),
            'length': (4, 6),
            'checksum': (6, 8)
        }
        self.data = bytearray(8)

    def __getitem__(self, item):
        if item in self.attr:
            l, r = self.attr[item]
            return int.from_bytes(self.data[l:r], 'big')

    def __setitem__(self, key, value):
        if key in self.attr:
            l, r = self.attr[key]
            self.data[l:r] = int.to_bytes(value, r - l, 'big')

    def get_payload(self):
        return self.data[8:]

    def set_payload(self, data):
        self.data[8:] = data

    def encode(self):
        return self.data

    def decode(self, buf):
        self.data = buf

    def set_checksum(self):
        pass


class Udp:
    def __init__(self):
        pass

    @staticmethod
    def prot_type():
        return 0x11

    def handle_packet(self, transport, packet: MetaPacket):
        packet.LOG_INFO("UDP TAKE")
        udp_packet = UdpPacketField()
        udp_packet.decode(packet.payload)

        packet.target_prot_type = UdpDev.prot_type()
        packet.sender_prot_type = self.prot_type()
        packet.port = udp_packet['dst_port']
        packet.payload = udp_packet.get_payload()
        packet.LOG_INFO("UDP -> UDP DEV")
        transport.deliver_demux(packet)

    def write_packet(self, network, packet: MetaPacket):
        # write in endpoint
        pass
