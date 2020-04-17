import logging
from link.link import Link


class Stack:
    def __init__(self):
        self.link_dev = None
        self.link_layer = None
        self.network_layer = None
        self.transport_layer = None

    def attch(self):
        self.link_dev.attach(self)

    def set_dev(self, dev):
        self.link_dev = dev

    def my_mac_addr(self):
        return self.link_dev.my_mac_addr()

    def my_ip_addr(self):
        return self.link_dev.my_ip_addr()

    def set_link_layer(self, link):
        self.link_layer = link

    def set_network_layer(self, network):
        self.network_layer = network

    def set_transport_layer(self, transport_config):
        # self.transport_layer = transport
        pass

    def register_link_protocol(self, link_protocol):
        if not self.link_layer:
            logging.error("[STACK] register link: " + link_protocol.prot_type())
            return
        logging.info("[STACK] register link: " + link_protocol.prot_type())
        self.link_layer.register(link_protocol)

    def register_network_protocol(self, network_protocol):
        if not self.link_layer:
            logging.error("[STACK] register network: " + network_protocol.prot_type())
            return
        logging.info("[STACK] register network: " + network_protocol.prot_type())
        self.network_layer.register(network_protocol)

    def register_transport_protocol(self, transport_protocol):
        if not self.link_layer:
            logging.error("[STACK] register transport: " + transport_protocol.prot_type())
            return
        logging.info("[STACK] register transport: " + transport_protocol.prot_type())
        self.transport_layer.register(transport_protocol)

    def deliver_link(self, link_packet):
        if not self.link_layer:
            return
        self.link_layer.handle_packet(link_packet)

    def deliver_network(self, network_packet) -> None:
        if not self.link_layer:
            return
        self.network_layer.handle_packet(network_packet)

    def deliver_transport(self, transport_packet) -> None:
        if not self.link_layer:
            return
        self.transport_layer.handle_packet(transport_packet)

    def write_dev(self, packet):
        self.link_dev.write_packet(packet)

