import logging
from link.ethernet import Ethernet
from stack.metapacket import MetaPacket
import util


class ArpPacketField:
    def __init__(self) -> None:
        self.attr = {
            "hard_type": (0, 2),
            "prot_type": (2, 4),
            "hard_size": (4, 5),
            "prot_size": (5, 6),
            "op": (6, 8),
            "sender_mac_addr": (8, 14),
            "sender_ip_addr": (14, 18),
            "target_mac_addr": (18, 24),
            "target_ip_addr": (24, 28)
        }
        self.data = bytearray(28)

    def __setitem__(self, key: str, value: int) -> None:
        l, r = self.attr[key]
        self.data[l:r] = int.to_bytes(value, r - l, 'big')

    def __getitem__(self, item: str) -> int:
        l, r = self.attr[item]
        value = self.data[l:r]
        return int.from_bytes(value, 'big')

    def set_ipv4_ethernet(self):
        self.__setitem__("hard_type", 0x0001)
        self.__setitem__("prot_type", 0x0800)
        self.__setitem__("hard_size", 0x06)
        self.__setitem__("prot_size", 0x04)

    def encode(self):
        return self.data

    def decode(self, buf: bytearray) -> None:
        self.data = buf

    def LOG_INFO(self, status):
        ms = "[%s] IP: %s, MAC: %s -> IP: %s, MAC: %s"
        logging.info(ms, status, util.ip_i2s(self["sender_ip_addr"]),
                     util.mac_i2s(self["sender_mac_addr"]),
                     util.ip_i2s(self["target_ip_addr"]),
                     util.mac_i2s(self["target_mac_addr"]))


class Arp:
    def __init__(self):
        pass

    @staticmethod
    def prot_type():
        return 0x0806

    def write_packet(self, link, packet: MetaPacket):
        pass

    def handle_packet(self, link, packet: MetaPacket) -> None:
        packet.LOG_INFO("ARP TAKE")
        arp_packet = ArpPacketField()
        arp_packet.decode(packet.payload)

        if arp_packet["op"] == 0x01:  # request
            arp_packet.LOG_INFO("ARP TAKE REQUEST")

            reply_packet = ArpPacketField()
            reply_packet.set_ipv4_ethernet()
            reply_packet["op"] = 0x02
            reply_packet["sender_mac_addr"] = link.my_mac_addr()
            reply_packet["target_ip_addr"] = arp_packet["sender_ip_addr"]
            reply_packet["sender_ip_addr"] = link.my_ip_addr()
            reply_packet["target_mac_addr"] = arp_packet["sender_mac_addr"]

            reply_packet.LOG_INFO("ARP SEND RESPONSE")
            packet.sender_prot_type = Arp.prot_type()
            packet.target_prot_type = Ethernet.prot_type()
            packet.payload = reply_packet.encode()
            packet.ip_addr = reply_packet["target_ip_addr"]
            packet.mac_addr= reply_packet["target_mac_addr"]
            packet.state = "OUT"
            packet.LOG_INFO("ARP -> ETHERNET")
            link.handle_packet(packet)

        if arp_packet["op"] == 0x02:  # reply
            arp_packet.LOG_INFO("ARP TAKE REPLY")
            link.add_cache(arp_packet["sender_ip_addr"], arp_packet["sender_mac_addr"])
