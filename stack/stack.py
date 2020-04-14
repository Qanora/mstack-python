import logging


class Stack:
    def __init__(self):
        self.link = None
        self.transport_protocol = {}
        self.network_protocol = {}

    def register_link(self, link):
        self.link = link

    def register_transport(self, transport):
        self.transport_protocol[transport.prot_type()] = transport

    def register_network(self, network):
        logging.info("register network: " + hex(network.prot_type()))
        self.network_protocol[network.prot_type()] = network.handle_packet

    def deliver_network(self, prot_type: bytearray, payload: bytearray) -> None:
        prot_type = int.from_bytes(prot_type, 'big')
        logging.info("deliver-: get network packet: " + str(hex(prot_type)))
        if prot_type in self.network_protocol:
            self.network_protocol[prot_type](self, payload)
        else:
            logging.error("deliver-: error network protocol type: " + hex(prot_type))

    def deliver_transport(self, prot_type: bytearray, payload: bytearray) -> None:
        pass


stack = Stack()