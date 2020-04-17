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
        if key == "payload":
            self.data += value
            return
        l, r = self.attr[key]
        self.data[l:r] = value

    def __getitem__(self, item):
        if item == "payload":
            return self.data[14:]
        if item == "prot_type":
            l,r = self.attr[item]
            return "%04x" % int.from_bytes(self.data[l:r], byteorder='big')
        l, r = self.attr[item]
        value = self.data[l:r]
        return value

    def set_payload(self, payload: bytearray) -> None:
        self.data += payload

    def decode(self, buf):
        self.data = buf

    def encode(self) -> bytearray:
        return self.data

    def LOG_INFO(self, status):
        logging.info("[ETHERNET][" + status + "]: " + self["prot_type"] + " FROM:" + util.bytes_to_string(
            self["src_mac_addr"]) + " TO:" + util.bytes_to_string(self["dst_mac_addr"]))


class Ethernet:
    def __init__(self):
        pass

    @staticmethod
    def prot_type():
        return "FFFF"

    def handle_packet(self, link, packet: MetaPacket):
        packet.LOG_INFO("RECV")

        e_packet = EthernetPacketField()
        e_packet.decode(packet.payload())
        e_packet.LOG_INFO("RECV")

        packet = MetaPacket(Ethernet.prot_type(), e_packet["prot_type"], e_packet["payload"])
        packet.set_mac_addr(e_packet["src_mac_addr"])
        packet.LOG_INFO("SEND")

        link.handle_packet(packet)

    def write_packet(self, link, packet: MetaPacket):
        packet.LOG_INFO("RECV")

        e_packet = EthernetPacketField()
        e_packet["dst_mac_addr"] = packet.mac_addr()
        e_packet["src_mac_addr"] = link.my_mac_addr()
        e_packet["prot_type"] = bytearray.fromhex(packet.sender_prot_type())
        e_packet.set_payload(packet.payload())

        e_packet.LOG_INFO("SEND")
        link.write_dev(e_packet.encode())
