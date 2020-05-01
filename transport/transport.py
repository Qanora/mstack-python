from stack.metapacket import MetaPacket
import logging


class Transport:
    def __init__(self, stack):
        self.stack = stack
        self.transport_protocol_handle = {}
        self.transport_protocol_write = {}

    def register(self, transport_protocol):
        prot_type = transport_protocol.prot_type()
        self.transport_protocol_handle[prot_type] = transport_protocol.handle_packet
        self.transport_protocol_write[prot_type] = transport_protocol.write_packet

    def handle_packet(self, packet: MetaPacket):
        if packet.state == "OUT":
            self.write_packet(packet)
        else:
            self.read_packet(packet)

    def write_packet(self, packet: MetaPacket):
        prot_type = packet.target_prot_type
        if prot_type in self.transport_protocol_write:
            self.transport_protocol_write[prot_type](self, packet)
        else:
            logging.error("[TRANSPORT] error write packet type:" + hex(prot_type))

    def read_packet(self, packet: MetaPacket):
        packet.LOG_INFO("TRANSPORT TAKE")
        prot_type = packet.target_prot_type
        if prot_type in self.transport_protocol_handle:
            self.transport_protocol_handle[prot_type](self, packet)
        else:
            logging.error("[TRANSPORT] error read packet type:" + hex(prot_type))

    def deliver_network(self, packet: MetaPacket):
        self.stack.deliver_network(packet)

    def deliver_demux(self, packet: MetaPacket):
        self.stack.deliver_demux(packet)