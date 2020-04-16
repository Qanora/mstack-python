import logging
from header.ethernet import Ethernet
from header.metapacket import MetaPacket
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

    def __setitem__(self, key: str, value: bytearray) -> None:
        l, r = self.attr[key]
        self.data[l:r] = value

    def __getitem__(self, item: str) -> bytearray:
        l, r = self.attr[item]
        value = self.data[l:r]
        return value

    def set_ipv4_ethernet(self):
        self.__setitem__("hard_type", bytearray.fromhex("0001"))
        self.__setitem__("prot_type", bytearray.fromhex("0800"))
        self.__setitem__("hard_size", bytearray.fromhex("06"))
        self.__setitem__("prot_size", bytearray.fromhex("04"))

    def encode(self):
        return self.data

    def decode(self, buf: bytearray) -> None:
        self.data = buf

    def LOG_INFO(self, status):
        logging.info("[ARP][" + status + "]:" + " [FROM] IP:" + util.ip_to_string(self["sender_ip_addr"])
                     + " MAC:" + util.bytes_to_string(self["sender_mac_addr"]) + " [TO] IP:" +
                     util.ip_to_string(self["target_ip_addr"]) + " MAC:" + util.bytes_to_string(self["target_mac_add"]))
class Arp:
    def __init__(self):
        pass

    @staticmethod
    def prot_type():
        return "0806"

    def write_packet(self, link, ip_addr: bytearray):
        pass
        # query_packet = ArpPacketField()
        # query_packet.set_ipv4_ethernet()
        # query_packet["op"] = bytearray.fromhex("0001")
        # query_packet["sender_mac_addr"] = link.my_mac_addr()
        # query_packet["target_mac_addr"] = bytearray.fromhex("FFFFFFFFFFFF")
        # query_packet["sender_ip_addr"] = link.my_ip_addr()
        # query_packet["target_ip_addr"] = ip_addr
        #
        # packet = Packet(self.prot_type(), Ethernet.prot_type(), query_packet.encode())
        #
        # link.write_packet(packet)
        # logging.info("[ARP] query send")

    def handle_packet(self, link, packet: MetaPacket) -> None:
        packet.LOG_INFO("RECV")

        arp_packet = ArpPacketField()
        arp_packet.decode(packet.payload())

        if arp_packet["op"] == bytes.fromhex("0001"):  # request
            arp_packet.LOG_INFO("RECV REQUEST")

            reply_packet = ArpPacketField()
            reply_packet.set_ipv4_ethernet()
            reply_packet["op"] = bytearray.fromhex("0002")
            reply_packet["sender_mac_addr"] = link.my_mac_addr()
            reply_packet["target_ip_addr"] = arp_packet["sender_ip_addr"]
            reply_packet["sender_ip_addr"] = link.my_ip_addr()
            reply_packet["target_mac_addr"] = arp_packet["sender_mac_addr"]

            arp_packet.LOG_INFO("SEND RESPONSE")

            packet = MetaPacket(Arp.prot_type(), Ethernet.prot_type(), reply_packet.encode())
            packet.set_ip_addr(reply_packet["target_ip_addr"])
            packet.set_mac_addr(reply_packet["target_mac_addr"])

            packet.LOG_INFO("SEND")
            link.write_packet(packet)

        if arp_packet["op"] == bytes.fromhex("0002"):  # reply
            link.add_cache(arp_packet["sender_ip_addr"], arp_packet["sender_mac_addr"])
            logging.info("[ARP] recv arp reply")
