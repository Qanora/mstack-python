import logging

from header.ethernet import Ethernet
from header.metapacket import MetaPacket
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
        return "0000"

    def my_mac_addr(self):
        return self.tuntap.mac_addr()

    def my_ip_addr(self):
        return self._my_ip_addr

    def attach(self, stack: Stack) -> None:
        self.stack = stack
        self.tuntap.add_read_callback(self.read_dispatch)
        self._is_attach = True

    def is_attach(self) -> bool:
        return self._is_attach

    def write_packet(self, link_packet) -> None:
        self.tuntap.no_blocking_write(link_packet)

    def handle_packet(self, link, packet: MetaPacket):
        logging.error("[DEV] should not handle packet")

    def deliver_link(self, link_packet: MetaPacket) -> None:
        self.stack.deliver_link(link_packet)

    def read_dispatch(self, buf) -> None:
        packet = MetaPacket("0000", Ethernet.prot_type(), buf)
        packet.set_mac_addr(bytearray.fromhex("000000000000"))
        self.deliver_link(packet)
