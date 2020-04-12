from route.route import Route
from stack.stack import stack
import logging


class ArpConfig:
    def __init__(self) -> None:
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
            "src_ethernet_addr": (8, 14),
            "src_ip_addr": (14, 18),
            "target_ethernet_addr": (18, 24),
            "target_ip_addr": (24, 28)
        }

        self.payload = bytearray(28)

    def __setitem__(self, key: str, value: str) -> None:
        l, r = self.attr[key]
        self.payload[l:r] = bytearray.fromhex(value)

    def __getitem__(self, item: str) -> int:
        l, r = self.attr[item]
        data = self.payload[l:r]
        return int.from_bytes(data, byteorder='big', signed=False)

    def set_ipv4_ethernet(self):
        self.__setitem__("hard_type", "0001")
        self.__setitem__("prot_type", "0800")
        self.__setitem__("hard_size", "06")
        self.__setitem__("prot_size", "04")

    def encode(self):
        return self.payload

    def deconde(self, buf: bytearray) -> None:
        self.payload = buf


class ArpCache:
    def __init__(self, arp_config: ArpConfig) -> None:
        self.arp_config = arp_config

    def is_vaild(self, ip_addr) -> bool:
        pass

    def add_cache(self) -> None:
        pass

    def mac_addr(self):
        return self.arp_config.mac_addr

    def ip_addr(self):
        return self.arp_config.ip_addr


class Arp:
    def __init__(self, arp_config: ArpConfig):
        self.arp_cache = ArpCache(arp_config)

    def handle_packet(self, route: Route, payload: bytearray) -> None:
        arp_packet = ArpPacketField()
        arp_packet.deconde(payload)

        if arp_packet["op"] == 1:  # request
            logging.info("arp-: recv arp request")
            # reply_packet = ArpPacketField()
            # reply_packet.set_ipv4_ethernet()
            # reply_packet["op"] = "02"
            # reply_packet["src_ethernet_addr"] = self.arp_cache.mac_addr()
            # reply_packet["src_ip_addr"] = self.arp_cache.ip_addr()
            # reply_packet["target_ip_addr"] = arp_packet["src_ethernet_addr"]

        if arp_packet["op"] == 2:  # reply
            logging.info("arp-: recv arp reply")


stack.register_network(Arp())
