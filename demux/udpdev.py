import asyncio

from demux.portmanager import PortManager
from stack.metapacket import MetaPacket
import logging


class UdpDev:
    def __init__(self):
        self.port_manager = PortManager()
        self.queues = {}

    @staticmethod
    def prot_type():
        return 0x01

    def new_endpoint(self):
        return UdpEndPoint(self)

    def allocate(self, ip_addr, port):
        if self.port_manager.allocate_port(port) is not None:
            logging.info("[UDP_DEC PORT] bind: %s:%d", ip_addr, port)
            self.register(ip_addr, port)
            return True
        return False

    def handle_packet(self, demux, packet: MetaPacket):
        packet.LOG_INFO("UDP_DEV TAKE")
        if not self.port_manager.is_available(packet.port):
            packet.LOG_INFO("!!NO END DEV!!")
        self.put_packet("", packet.port, packet.payload)


    def write_packet(self, demux, packet: MetaPacket):
        pass

    def put_packet(self, ip_addr, port, packet):
        q = self.queues[port]
        try:
            q.put_nowait(packet)
        except asyncio.QueueFull:
            logging.info("[!!UDP RECV BUFFER FULL!!]")
            pass

    async def get_packet(self, ip_addr, port):
        q = self.queues[port]
        packet = await q.get()
        q.task_done()
        return packet

    def register(self, ip_addr, port):
        self.queues[port] = asyncio.Queue(2000)


class UdpEndPoint:
    def __init__(self, udp):
        self.udp = udp
        self.ip_addr = None
        self.port = None

    def bind(self, ip_addr, port):
        if self.udp.allocate(ip_addr, port):
            self.ip_addr = ip_addr
            self.port = port
            return True
        return False

    def listen(self):
        pass

    def accept(self):
        pass

    async def read(self):
        buf = await self.udp.get_packet(self.ip_addr, self.port)
        return buf

    def write(self):
        pass

    def connect(self):
        pass
