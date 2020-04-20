from header.metapacket import MetaPacket
import logging


class Network:
    def __init__(self, stack):
        self.stack = stack
        self.network_protocol_handle = {}
        self.network_protocol_write = {}

    def my_ip_addr(self) -> int:
        return self.stack.my_ip_addr()

    def register(self, network_protocol):
        prot_type = network_protocol.prot_type()
        self.network_protocol_handle[prot_type] = network_protocol.handle_packet
        self.network_protocol_write[prot_type] = network_protocol.write_packet

    def handle_packet(self, packet: MetaPacket):
        if packet.is_write():
            self.write_packet(packet)
        else:
            self.read_packet(packet)

    def write_packet(self, packet: MetaPacket):
        prot_type = packet.target_prot_type()
        if prot_type in self.network_protocol_write:
            self.network_protocol_write[prot_type](self, packet)
        else:
            logging.error("[NETWORK] error write packet type:" + hex(prot_type))

    def read_packet(self, packet: MetaPacket):
        packet.LOG_INFO("NETWORK TAKE")
        prot_type = packet.target_prot_type()
        if prot_type in self.network_protocol_handle:
            self.network_protocol_handle[prot_type](self, packet)
        else:
            logging.error("[NETWORK] error handle packet type:" + hex(prot_type))

    def deliver_link(self, packet: MetaPacket):
        self.stack.deliver_link(packet)

    def deliver_transport(self, packet: MetaPacket):
        self.stack.deliver_transport(packet)
