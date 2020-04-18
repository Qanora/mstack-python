import logging

from header.ipv4 import Ipv4
from header.metapacket import MetaPacket
from network.network import Network


class IcmpPacketField:
    def __init__(self):
        self.attr = {
            "prot_type": (0, 1),
            "code": (1, 2),
            "checksum": (2, 4),
            "id": (4, 6),
            "seq": (6, 8)
        }
        self.data = bytearray(8)

    def set_checksum(self):
        self['checksum'] = 0x0000
        bt = 0
        for i in range(0, len(self.data), 2):
            bt += int.from_bytes(self.data[i:i+2], 'little')
        bt = (bt >> 16) + (bt & 0xff)
        bt = (~bt) & 0xffff
        self['checksum'] = bt

    def __setitem__(self, key, value: int):
        if key in self.attr:
            l, r = self.attr[key]
            self.data[l:r] = int.to_bytes(value, r - l, 'big')

    def __getitem__(self, item):
        if item in self.attr:
            l, r = self.attr[item]
            return int.from_bytes(self.data[l:r], 'big')

    def get_payload(self):
        return self.data[8:]

    def set_payload(self, data):
        self.data[8:] = data

    def encode(self):
        return self.data

    def decode(self, buf):
        self.data = buf

    def LOG_INFO(self, status):
        ms = "[%s] [%s]"
        logging.info(ms, status, hex(self['prot_type']))


class ICMP:
    def __init__(self):
        pass

    @staticmethod
    def prot_type():
        return 0x0001

    def write_packet(self, network: Network, packet: MetaPacket):
        pass

    def handle_packet(self, network: Network, packet: MetaPacket):
        icmp_packet = IcmpPacketField()
        icmp_packet.decode(packet.payload())
        icmp_packet.LOG_INFO("ICMP TAKE")
        if icmp_packet["prot_type"] == 8:
            icmp_packet.LOG_INFO("ICMP TAKE ECHO REQUEST")

            reply_packet = IcmpPacketField()
            reply_packet["prot_type"] = 0x00
            reply_packet["seq"] = icmp_packet["seq"]
            reply_packet["code"] = 0x00
            reply_packet["id"] = icmp_packet["id"]
            reply_packet.set_payload(icmp_packet.get_payload())
            reply_packet.set_checksum()

            packet = MetaPacket(packet.target_prot_type(), Ipv4.prot_type(), reply_packet)
            packet.set_ip_addr(packet.ip_addr())
            packet.LOG_INFO("ICMP -> IPV4")
            network.write_packet(packet)