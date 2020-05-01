from stack.metapacket import MetaPacket
import logging


class Demux:
    def __init__(self, stack):
        self.stack = stack
        self.demux_protocol_handle = {}
        self.demux_protocol_write = {}
        self.demux_protocol_new_endpoint = {}

    def new_endpoint(self, prot_type):
        if prot_type in self.demux_protocol_new_endpoint:
            return self.demux_protocol_new_endpoint[prot_type]()
        logging.error("[DEMUX] new endpoint: " + hex(prot_type))
        return None

    def register(self, demux_protocol):
        prot_type = demux_protocol.prot_type()
        self.demux_protocol_handle[prot_type] = demux_protocol.handle_packet
        self.demux_protocol_write[prot_type] = demux_protocol.write_packet
        self.demux_protocol_new_endpoint[prot_type] = demux_protocol.new_endpoint

    def handle_packet(self, packet: MetaPacket):
        if packet.state == "OUT":
            self.write_packet(packet)
        else:
            self.read_packet(packet)

    def write_packet(self, packet: MetaPacket):
        prot_type = packet.target_prot_type
        if prot_type in self.demux_protocol_write:
            self.demux_protocol_write[prot_type](self, packet)
        else:
            logging.error("[DEMUX] error write packet type:" + hex(prot_type))

    def read_packet(self, packet: MetaPacket):
        packet.LOG_INFO("DEMUX TAKE")
        prot_type = packet.target_prot_type
        if prot_type in self.demux_protocol_handle:
            self.demux_protocol_handle[prot_type](self, packet)
        else:
            logging.error("[DEMUX] error read packet type:" + hex(prot_type))

    def deliver_network(self, packet: MetaPacket):
        self.stack.deliver_network(packet)
