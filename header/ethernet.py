import logging
from header.metapacket import MetaPacket
import util


class EthernetPacketField:
    def __init__(self) -> None:
        self.data = bytearray(14)
        self.attr = {
            "dst_mac_addr": (0, 6),
            "src_mac_addr": (6, 12),
            "prot_type": (12, 14),
        }

    def __setitem__(self, key, value):
        l, r = self.attr[key]
        self.data[l:r] = int.to_bytes(value, r - l, 'big')

    def set_payload(self, payload:bytearray) -> None:
        self.data[14:] = payload

    def __getitem__(self, item):
        l, r = self.attr[item]
        value = self.data[l:r]
        return int.from_bytes(value, 'big')

    def get_payload(self) -> bytearray:
        return self.data[14:]

    def decode(self, buf):
        self.data = buf

    def encode(self) -> bytearray:
        return self.data

    def LOG_INFO(self, status:str):
        ms = "[%s]: [%s] [%s -> %s]"
        prot_type = hex(self["prot_type"])
        src_mac_addr = util.mac_i2s(self["src_mac_addr"])
        dst_mac_addr = util.mac_i2s(self["dst_mac_addr"])
        logging.info(ms, status, prot_type, src_mac_addr, dst_mac_addr)

class Ethernet:
    def __init__(self):
        pass

    @staticmethod
    def prot_type():
        return 0xFFFF

    def handle_packet(self, link, packet: MetaPacket):

        e_packet = EthernetPacketField()
        e_packet.decode(packet.payload())

        packet = MetaPacket(Ethernet.prot_type(), e_packet["prot_type"], e_packet.get_payload())
        packet.set_mac_addr(e_packet["src_mac_addr"])

        packet.LOG_INFO("ETHERNET -> LINK")
        link.handle_packet(packet)

    def write_packet(self, link, packet: MetaPacket):
        packet.LOG_INFO("ETHERNET TAKE")

        e_packet = EthernetPacketField()
        e_packet["dst_mac_addr"] = packet.mac_addr()
        e_packet["src_mac_addr"] = link.my_mac_addr()
        e_packet["prot_type"] = packet.sender_prot_type()
        e_packet.set_payload(packet.payload())

        packet = MetaPacket(self.prot_type(), 0x0000, e_packet.encode())
        packet.LOG_INFO("ETHERNET -> DEV")
        link.write_packet(packet)
