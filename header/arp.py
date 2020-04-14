import logging

from header.ethernet import EthernetPacketField


class ArpConfig:
    def __init__(self) -> None:
        self.prot_type = 0x0806
        self.ip_addr = None
        self.mac_addr = None


class ArpPacketField:
    def __init__(self) -> None:
        self.attr = {
            "hard_type": (0, 2),
            "prot_type": (2, 4),
            "hard_size": (4, 5),
            "prot_size": (5, 6),
            "op": (6, 8),
            "sender_ethernet_addr": (8, 14),
            "sender_ip_addr": (14, 18),
            "target_ethernet_addr": (18, 24),
            "target_ip_addr": (24, 28)
        }

        self.payload = bytearray(28)

    def __setitem__(self, key: str, value: bytearray) -> None:
        l, r = self.attr[key]
        self.payload[l:r] = value

    def __getitem__(self, item: str) -> bytearray:
        l, r = self.attr[item]
        data = self.payload[l:r]
        return data

    def set_ipv4_ethernet(self):
        self.__setitem__("hard_type", bytearray.fromhex("0001"))
        self.__setitem__("prot_type", bytearray.fromhex("0800"))
        self.__setitem__("hard_size", bytearray.fromhex("06"))
        self.__setitem__("prot_size", bytearray.fromhex("04"))

    def encode(self):
        return self.payload

    def deconde(self, buf: bytearray) -> None:
        self.payload = buf


class ArpCache:
    def __init__(self) -> None:
        self.cache = {}

    def is_vaild(self, ip_addr) -> bool:
        pass

    def add_cache(self, ip_addr: bytearray, mac_addr: bytearray) -> None:
        self.cache[bytes(ip_addr)] = mac_addr

    def query_by_ip(self, ip_addr: bytearray):
        if bytes(ip_addr) not in self.cache:
            return None
        return self.cache[bytes(ip_addr)]


class Arp:
    def __init__(self, arp_config: ArpConfig):
        self.arp_config = arp_config
        self.arp_cache = ArpCache()

    def prot_type(self):
        return self.arp_config.prot_type

    def handle_packet(self, stack, payload: bytearray) -> None:
        arp_packet = ArpPacketField()
        arp_packet.deconde(payload)
        if arp_packet["op"] == bytes.fromhex("0001"):  # request
            logging.info("arp-: recv arp request")
            reply_packet = ArpPacketField()
            reply_packet.set_ipv4_ethernet()
            reply_packet["op"] = bytearray.fromhex("0002")

            reply_packet["sender_ethernet_addr"] = self.arp_config.mac_addr()
            reply_packet["target_ip_addr"] = arp_packet["sender_ip_addr"]
            reply_packet["sender_ip_addr"] = self.arp_config.ip_addr()

            e_packet = EthernetPacketField()
            e_packet.dst_mac_addr = arp_packet["sender_ethernet_addr"]
            e_packet.src_mac_addr = self.arp_config.mac_addr()
            e_packet.type = bytearray.fromhex("0806")
            e_packet.payload = reply_packet.encode()

            stack.link.write_packet(e_packet)
            logging.info("arp-: finish arp request")

        if arp_packet["op"] == bytes.fromhex("0002"):  # reply
            logging.info("arp-: recv arp reply")

        self.arp_cache.add_cache(arp_packet["sender_ip_addr"], arp_packet["sender_ethernet_addr"])
