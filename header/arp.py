from route.route import Route


class ArpConfig:
    def __init__(self) -> None:
        pass


class ArpPacketField:
    def __init__(self) -> None:
        self.attr = {
            "hard_type": (0,2),
            "prot_type": (2, 4),
            "hard_size": (4, 5),
            "prot_size": (5, 7),
            "src_ethernet_addr": (7, 13),
            "src_ip_addr": (13, 17),
            "target_ethernet_addr": (17, 23),
            "target_ip_addr": (23, 27)
        }

        self.payload = bytearray(28)

    def __setitem__(self, key: str, value: bytearray) -> None:
        l, r = self.attr[key]
        self.payload[l:r] = value

    def __getitem__(self, item: str) -> bytearray:
        l, r = self.attr[item]
        return self.payload[l:r]

    def encode(self):
        return self.payload

    def deconde(self, buf: bytearray) -> None:
        self.payload = buf


class Arp:
    def __init__(self):
        pass

    def handle_packet(self, route: Route, payload: bytearray) -> None:
        arp_packet = ArpPacketField()
        arp_packet.deconde(payload)
        print(arp_packet["src_ethernet_addr"])