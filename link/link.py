import logging
import asyncio
from stack.metapacket import MetaPacket
from link.arp import ArpPacketField


def write_arp_packet(link, ip_addr: int):
    query_packet = ArpPacketField()
    query_packet.set_ipv4_ethernet()
    query_packet["op"] = 0x0001
    query_packet["sender_mac_addr"] = link.my_mac_addr()
    query_packet["target_mac_addr"] = 0xFFFFFFFFFFFF
    query_packet["sender_ip_addr"] = link.my_ip_addr()
    query_packet["target_ip_addr"] = ip_addr

    query_packet.LOG_INFO("SEND REQUEST")
    packet = MetaPacket(0x8060, 0xFFFF, query_packet.encode())

    link.write_packet(packet)


class ArpCache:
    def __init__(self):
        self.cache = {}

    def add_cache(self, ip_addr: int, mac_addr: int):
        self.cache[ip_addr] = mac_addr

    def query(self, ip_addr: int):
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
        if packet.ip_addr is not None and packet.mac_addr is not None:
            self.arp_cache.add_cache(packet.ip_addr, packet.mac_addr)
            packet.LOG_INFO("ARP CACHE")
        elif packet.mac_addr is None and packet.ip_addr is not None:
            while True:
                mac_addr = self.arp_cache.query(packet.ip_addr)
                if mac_addr is not None:
                    packet.set_mac_addr = mac_addr
                    packet.LOG_INFO("ARP QUERY")
                    break
                write_arp_packet(self, packet.ip_addr)
                asyncio.sleep(0.2)
        return packet

    def add_cache(self, ip_addr, mac_add):
        self.arp_cache.add_cache(ip_addr, mac_add)

    def handle_packet(self, packet: MetaPacket):
        if packet.state == "OUT":
            self.write_packet(packet)
        else:
            self.read_packet(packet)

    def read_packet(self, packet: MetaPacket):
        packet = self.hook_ip_mac(packet)
        prot_type = packet.target_prot_type
        if prot_type in self.link_protocol_handle:
            packet.LOG_INFO("LINK TAKE")
            self.link_protocol_handle[prot_type](self, packet)
        else:
            packet.LOG_INFO("LINK -> NETWORK")
            self.stack.deliver_network(packet)

    def write_packet(self, packet: MetaPacket):
        packet = self.hook_ip_mac(packet)
        prot_type = packet.target_prot_type
        if prot_type in self.link_protocol_write:
            packet.LOG_INFO("LINK TAKE")
            self.link_protocol_write[prot_type](self, packet)
        else:
            logging.error("[LINK] error write packet type:" + hex(prot_type))

