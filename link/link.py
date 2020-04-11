from header.ethernet import EthernetConfig
from header.ethernet import EthernetPacketField
from link.tuntap import Tuntap
from stack.nic import Nic


class Link:
    def __init__(self, fd: Tuntap, link_field: EthernetConfig) -> None:
        self.fd = fd
        self.mtu = link_field.mtu
        self.mac_addr = link_field.mac_addr
        self.dispatcher = None

    def attach(self, dispatcher: Nic) -> None:
        self.dispatcher = dispatcher
        self.dispatch_loop()

    def is_attach(self) -> bool:
        pass

    def write_packet(self, link_packet: EthernetPacketField) -> None:
        if self.mac_addr and link_packet.dst_mac_addr and self.mac_addr == link_packet.dst_mac_addr:
            self.deliver(link_packet.payload)
        if not link_packet.src_mac_addr:
            link_packet.src_mac_addr = self.mac_addr

        self.fd.no_blocking_write(link_packet.encode())

    def deliver(self, link_payload: bytearray) -> None:
        self.dispatcher.deliver(link_payload)

    def dispatch(self) -> None:
        buf = self.fd.no_blocking_read(self.mtu)
        link_packet = EthernetPacketField()
        link_packet.decode(buf)
        print(link_packet.src_mac_addr.hex(), link_packet.dst_mac_addr.hex())
        self.deliver(link_packet.payload)

    def dispatch_loop(self) -> None:
        while True:
            self.dispatch()
