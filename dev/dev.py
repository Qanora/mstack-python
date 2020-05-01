import logging

from link.ethernet import Ethernet
from stack.metapacket import MetaPacket
from dev.tuntap import Tuntap
from stack.stack import Stack


class Dev:
    def __init__(self, tuntap: Tuntap, _my_ip_addr) -> None:
        self.tuntap = tuntap
        self.stack = None
        self._is_attach = False
        self._my_ip_addr = _my_ip_addr

    @staticmethod
    def prot_type():
        return 0x0000

    def my_mac_addr(self) -> int:
        return int.from_bytes(self.tuntap.mac_addr(), 'big')

    def my_ip_addr(self) -> int:
        return self._my_ip_addr

    def attach(self, stack: Stack) -> None:
        self.stack = stack
        self.tuntap.add_read_callback(self.read_dispatch)
        self._is_attach = True

    def is_attach(self) -> bool:
        return self._is_attach

    def write_packet(self, link, packet: MetaPacket) -> None:
        packet.LOG_INFO("DEV SEND")
        self.tuntap.no_blocking_write(packet.payload)

    def handle_packet(self, link, packet: MetaPacket):
        logging.error("[DEV] should not handle packet")

    def read_dispatch(self, buf) -> None:
        packet = MetaPacket(0x0000, Ethernet.prot_type(), buf)
        packet.LOG_INFO("DEV -> ETHERNET")
        self.stack.deliver_link(packet)
