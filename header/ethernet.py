class EthernetConfig:
    def __init__(self, mtu: int, mac_addr: bytes) -> None:
        self.mtu = mtu
        self.mac_addr = mac_addr


class EthernetPacketField:
    def __init__(self) -> None:
        self.src_mac_addr = None
        self.dst_mac_addr = None
        self.type = None
        self.payload = None

    def encode(self) -> bytearray:
        return self.dst_mac_addr + self.src_mac_addr + self.type + self.payload

    def decode(self, buf: bytearray) -> None:
        self.src_mac_addr = buf[:6]
        self.dst_mac_addr = buf[6:12]
        self.type = buf[12:14]
        self.payload = buf[14:]
