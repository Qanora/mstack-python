from link.ethernet import Ethernet
from stack.metapacket import MetaPacket
from network.network import Network
import logging
import util

class Ipv4PacketField:
    def __init__(self):
        self.attr = {
            "version+ihl": (0, 1),
            "type_of_service": (1, 2),
            "total_length": (2, 4),
            "id": (4, 6),
            "r+df+mf+fo": (6, 8),
            "ttl": (8, 9),
            "prot_type": (9, 10),
            "header_checksum": (10, 12),
            "src_ip_addr": (12, 16),
            "dst_ip_addr": (16, 20),
        }
        self.data = bytearray(20)

    def get_header_length(self):
        ihl = self['ihl']
        return ihl*4

    def set_checksum(self):
        self['header_checksum'] = 0x0000
        bt = 0
        for i in range(0, self.get_header_length(), 2):
            bt += int.from_bytes(self.data[i:i + 2], 'big')
        bt = (bt >> 16) + (bt & 0xffff)
        bt += (bt >> 16)
        bt = (~bt) & 0xffff
        self['header_checksum'] = bt

    def set_ipv4_packet(self):
        l, r = self.attr['version+ihl']
        self.data[l:r] = bytearray.fromhex("45")
        l, r = self.attr['type_of_service']
        self.data[l:r] = bytearray.fromhex("00")
        l, r = self.attr['ttl']
        self.data[l:r] = bytearray.fromhex("40")
        l, r = self.attr['r+df+mf+fo']
        self.data[l:r] = bytearray.fromhex("0000")

    def __getitem__(self, item) -> int:
        if item == 'version':
            data = self["version+ihl"]
            return data >> 4

        if item == 'ihl':
            data = self["version+ihl"]
            return data & 0xf

        if item == 'r':
            data = self["r+df+mf+fo"]
            return data >> 15

        if item == 'df':
            data = self["r+df+mf+fo"]
            return (data >> 14) & 0x1

        if item == 'mf':
            data = self["r+df+mf+fo"]
            return (data >> 13) & 0x1

        if item == 'fo':
            data = self["r+df+mf+fo"]
            return (data & ((1 << 13) - 1)) * 8

        if item in self.attr:
            l, r = self.attr[item]
            return int.from_bytes(self.data[l:r], byteorder='big')

    def __setitem__(self, key: str, value: int):
            l, r = self.attr[key]
            self.data[l:r] = int.to_bytes(value, r - l, 'big')

    def get_payload(self) -> bytearray:
        l = self['ihl']
        return self.data[l*4:]

    def add_payload(self, value):
        self.data += value

    def encode(self) -> bytearray:
        return self.data

    def decode(self, buf):
        self.data = buf

    def is_valid(self) -> bool:
        return True

    def get_total_length(self) -> int:
        return len(self.data)

    def LOG_INFO(self, status):
        ms = "[%s]: [%s] [%s -> %s]"
        logging.info(ms, status, hex(self['prot_type']), util.ip_i2s(self['src_ip_addr']),
                     util.ip_i2s(self['dst_ip_addr']))
import collections
import heapq


class Holds:
    def __init__(self, first, last, delete):
        self.first = first
        self.last = last
        self.delete = delete


class Ipv4Fragments:
    def __init__(self):
        self.holes = collections.defaultdict(lambda: [Holds(0, 65535, False)])
        self.counter = collections.defaultdict(lambda: 0)
        self.reassemblers = collections.defaultdict(list)

    def add_fragments(self, ipv4_packet: Ipv4PacketField):
        key = self.hash(ipv4_packet)
        first = ipv4_packet["fo"]
        last = ipv4_packet["fo"] + len(ipv4_packet.get_payload())

        if self.update_holes(key, first, last, ipv4_packet["mf"] != 0):
            heapq.heappush(self.reassemblers[key], (first, ipv4_packet))

        if self.counter[key] < len(self.holes[key]):
            return None
        _, packed_ipv4_packet = heapq.heappop(self.reassemblers[key])
        while self.reassemblers[key]:
            _, ipv4_packet = heapq.heappop(self.reassemblers[key])
            packed_ipv4_packet.add_payload(ipv4_packet.get_payload())

        del self.counter[key]
        del self.reassemblers[key]
        del self.holes[key]

        return packed_ipv4_packet

    def update_holes(self, key, first, last, more) -> bool:
        used = False
        holes = self.holes[key]
        for i in range(len(holes)):
            if holes[i].delete or first > holes[i].last or last < holes[i].first:
                continue
            used = True
            self.counter[key] += 1
            self.holes[key][i].delete = True
            if first > holes[i].first:
                self.holes[key].append(Holds(holes[i].first, first - 1, False))
            if last < holes[i].last and more:
                self.holes[key].append(Holds(last + 1, holes[i].last, False))
        return used

    def hash(self, ipv4_packet):
        id = ipv4_packet["id"]
        prot_type = ipv4_packet["prot_type"]
        src_ip_addr = ipv4_packet["src_ip_addr"]
        dst_ip_addr = ipv4_packet["dst_ip_addr"]
        return id, prot_type, src_ip_addr, dst_ip_addr

    #TODO
    def cut(self, ipv4_packt: Ipv4PacketField) -> [Ipv4PacketField]:
        return []


class Ipv4:
    def __init__(self):
        self.ipv4_fragments = Ipv4Fragments()
        self.id = 0

    @staticmethod
    def prot_type():
        return 0x0800

    def handle_packet(self, network: Network, packet: MetaPacket) -> None:
        packet.LOG_INFO("IPV4 TAKE")
        ipv4_packet = Ipv4PacketField()
        ipv4_packet.decode(packet.payload)
        if not ipv4_packet.is_valid():
            return

        ipv4_packet = self.ipv4_fragments.add_fragments(ipv4_packet)
        if ipv4_packet is None:
            return

        packet.sender_prot_type = self.prot_type()
        packet.target_prot_type = ipv4_packet["prot_type"]
        packet.payload = ipv4_packet.get_payload()
        packet.ip_addr = ipv4_packet["src_ip_addr"]
        packet.LOG_INFO("IPV4 -> NETWORK")

        network.handle_packet(packet)

    def write_packet(self, network: Network, packet: MetaPacket) -> None:
        ipv4_packet = Ipv4PacketField()
        ipv4_packet.set_ipv4_packet()
        ipv4_packet.LOG_INFO("IPV4 TAKE")
        ipv4_packet["prot_type"] = packet.sender_prot_type
        ipv4_packet["src_ip_addr"] = network.my_ip_addr()
        ipv4_packet["dst_ip_addr"] = packet.ip_addr
        ipv4_packet["id"] = self.id
        self.id += 1

        ipv4_packet.add_payload(packet.payload)
        ipv4_packet["total_length"] = ipv4_packet.get_total_length()
        ipv4_packet.set_checksum()

        packet.sender_prot_type = self.prot_type()
        packet.target_prot_type = Ethernet.prot_type()
        packet.payload = ipv4_packet.encode()
        packet.LOG_INFO("IPV4 -> ETHERNET")
        network.deliver_link(packet)
