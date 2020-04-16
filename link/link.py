import logging
import asyncio
from header.metapacket import MetaPacket
from header.arp import ArpPacketField


def write_packet(link, ip_addr: bytearray):
    query_packet = ArpPacketField()
    query_packet.set_ipv4_ethernet()
    query_packet["op"] = bytearray.fromhex("0001")
    query_packet["sender_mac_addr"] = link.my_mac_addr()
    query_packet["target_mac_addr"] = bytearray.fromhex("FFFFFFFFFFFF")
    query_packet["sender_ip_addr"] = link.my_ip_addr()
    query_packet["target_ip_addr"] = ip_addr

    packet = MetaPacket("0806", "FFFF", query_packet.encode())

    link.write_packet(packet)
    logging.info("[LINK] query send")

class ArpCache:
    def __init__(self):
        self.cache = {}

    def add_cache(self, ip_addr: bytearray, mac_addr: bytearray):
        ip_addr = int.from_bytes(ip_addr, 'big')
        self.cache[ip_addr] = mac_addr

    def query(self, ip_addr: bytearray):
        ip_addr = int.from_bytes(ip_addr, 'big')
        if ip_addr in self.cache:
            return self.cache[ip_addr]
        else:
            return None

class Link:
    def __init__(self, stack):
        self.stack = stack
        self.arp_cache = ArpCache()
        self.link_protocol_handle = {}
        self.link_protocol_write = {}

    def my_ip_addr(self):
        return self.stack.my_ip_addr()

    def my_mac_addr(self):
        return self.stack.my_mac_addr()

    def register(self, link_protocol):
        prot_type = link_protocol.prot_type()
        self.link_protocol_handle[prot_type] = link_protocol.handle_packet
        self.link_protocol_write[prot_type] = link_protocol.write_packet

    def hook_ip_mac(self, packet: MetaPacket):
        if packet.ip_addr() is not None and packet.mac_addr() is not None:
            self.arp_cache.add_cache(packet.ip_addr(), packet.mac_addr())
        elif packet.mac_addr() is None:
            while True:
                mac_addr = self.arp_cache.query(packet.ip_addr())
                if mac_addr is not None:
                    packet.set_mac_addr(mac_addr)
                    break
                write_packet(self, packet.ip_addr())
                asyncio.sleep(0.2)
        return packet

    def add_cache(self, ip_addr, mac_add):
        self.arp_cache.add_cache(ip_addr, mac_add)

    def handle_packet(self, packet: MetaPacket):
        packet = self.hook_ip_mac(packet)
        prot_type = packet.target_prot_type()
        if prot_type in self.link_protocol_handle:
            self.link_protocol_handle[prot_type](self, packet)
        else:
            logging.error("[LINK] error handle packet type:" + prot_type)

    def write_packet(self, packet: MetaPacket):
        packet = self.hook_ip_mac(packet)
        prot_type = packet.target_prot_type()
        if prot_type in self.link_protocol_write:
            self.link_protocol_write[prot_type](self, packet)
        else:
            logging.error("[LINK] error write packet type:" + prot_type)

    def write_dev(self, packet):
        self.stack.write_dev(packet)