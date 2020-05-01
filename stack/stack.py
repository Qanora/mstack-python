import logging
from stack.metapacket import MetaPacket


class Stack:
    def __init__(self):
        self.link_dev = None
        self.link_layer = None
        self.network_layer = None
        self.transport_layer = None
        self.demux_layer = None

    def attch(self):
        self.link_dev.attach(self)

    def set_dev(self, dev):
        self.link_dev = dev

    def my_mac_addr(self) -> int:
        return self.link_dev.my_mac_addr()

    def my_ip_addr(self) -> int:
        return self.link_dev.my_ip_addr()

    def set_link_layer(self, link):
        self.link_layer = link

    def set_network_layer(self, network):
        self.network_layer = network

    def set_transport_layer(self, transport):
        self.transport_layer = transport

    def set_demux_layer(self, dumux):
        self.demux_layer = dumux

    def register_link_protocol(self, link_protocol):
        if not self.link_layer:
            logging.error("[STACK] register link: " + hex(link_protocol.prot_type()))
            return
        logging.info("[STACK] register link: " + hex(link_protocol.prot_type()))
        self.link_layer.register(link_protocol)

    def register_network_protocol(self, network_protocol):
        if not self.network_layer:
            logging.error("[STACK] register network: " + hex(network_protocol.prot_type()))
            return
        logging.info("[STACK] register network: " + hex(network_protocol.prot_type()))
        self.network_layer.register(network_protocol)

    def register_transport_protocol(self, transport_protocol):
        if not self.transport_layer:
            logging.error("[STACK] register transport: " + hex(transport_protocol.prot_type()))
            return
        logging.info("[STACK] register transport: " + hex(transport_protocol.prot_type()))
        self.transport_layer.register(transport_protocol)

    def register_demux_dev(self, demux_dev):
        if not self.demux_layer:
            logging.error("[STACK] register demux dev: " + hex(demux_dev.prot_type()))
        logging.info("[STACK] register demux dev: " + hex(demux_dev.prot_type()))
        self.demux_layer.register(demux_dev)

    def deliver_link(self, link_packet: MetaPacket):
        if not self.link_layer:
            return
        self.link_layer.handle_packet(link_packet)

    def deliver_network(self, network_packet: MetaPacket) -> None:
        if not self.network_layer:
            return
        self.network_layer.handle_packet(network_packet)

    def deliver_transport(self, transport_packet: MetaPacket) -> None:
        if not self.transport_layer:
            return
        self.transport_layer.handle_packet(transport_packet)

    def deliver_demux(self, demux_packet: MetaPacket):
        if not self.demux_layer:
            return
        self.demux_layer.handle_packet(demux_packet)

    def new_endpoint(self, transport_prot_type):
        return self.demux_layer.new_endpoint(transport_prot_type)