from header.ethernet import EthernetConfig
from header.ethernet import EthernetPacketField
from link.tuntap import Tuntap
from stack.nic import Nic
import asyncio
import logging


class Link:
    def __init__(self, fd: Tuntap, link_field: EthernetConfig) -> None:
        self.fd = fd
        self.mtu = link_field.mtu
        self.mac_addr = link_field.mac_addr
        self.dispatcher = None
        self.is_attach = False

    def attach(self, dispatcher: Nic) -> None:
        self.dispatcher = dispatcher
        self.fd.add_read_callback(self.dispatch_loop_by_callback)
        loop = asyncio.get_event_loop()
        self.is_attach = True

    def is_attach(self) -> bool:
        return self.is_attach

    def write_packet(self, link_packet: EthernetPacketField) -> None:
        if self.mac_addr and link_packet.dst_mac_addr and self.mac_addr == link_packet.dst_mac_addr:
            self.deliver(link_packet.type, link_packet.payload)
        if not link_packet.src_mac_addr:
            link_packet.src_mac_addr = self.mac_addr

        self.fd.no_blocking_write(link_packet.encode())

    def deliver(self, prot_type: bytearray, link_payload: bytearray) -> None:
        self.dispatcher.deliver_network(prot_type, link_payload)

    # def dispatch_loop(self) -> None:
    #     for buf in self.fd.blocking_read(self.mtu):
    #         link_packet = EthernetPacketField()
    #         link_packet.decode(buf)
    #         logging.info("link-: src:" + link_packet.src_mac_addr.hex() + " dst:" + link_packet.dst_mac_addr.hex())
    #         self.deliver(link_packet.payload)

    def dispatch_loop_by_callback(self, buf) -> None:
        link_packet = EthernetPacketField()
        link_packet.decode(buf)
        logging.info("link-: src:" + link_packet.src_mac_addr.hex() + " dst:" + link_packet.dst_mac_addr.hex())
        self.deliver(link_packet.type, link_packet.payload)