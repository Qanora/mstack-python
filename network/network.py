from header.metapacket import MetaPacket
import logging


class Network:
    def __init__(self, stack):
        self.stack = stack
        self.network_protocol_handle = {}
        self.network_protocol_write = {}

    def register(self, network_protocol):
        prot_type = network_protocol.prot_type()
        self.network_protocol_handle[prot_type] = network_protocol.handle_packet
        self.network_protocol_write[prot_type] = network_protocol.write_packet

    def write_packet(self, packet: MetaPacket):
        prot_type = packet.target_prot_type()
        if prot_type in self.network_protocol_write:
            self.network_protocol_handle[prot_type](self, packet)
        else:
            logging.error("[NETWORK] error write packet type:" + prot_type)

    def handle_packet(self, packet: MetaPacket):
        packet.LOG_INFO("NETWORK RECV")
        prot_type = packet.target_prot_type()
        if prot_type in self.network_protocol_handle:
            self.network_protocol_handle[prot_type](self, packet)
        else:
            logging.error("[NETWORK] error handle packet type:" + prot_type)

    def write_link(self, packet: MetaPacket):
        self.stack.deliver_link(packet)

    def write_transport(self, packet: MetaPacket):
        self.stack.deliver_transport(packet)