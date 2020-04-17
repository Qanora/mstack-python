from header.ethernet import Ethernet
from header.metapacket import MetaPacket
from network.network import Network


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

    def __getitem__(self, item):
        if item == 'payload':
            ihl = self['ihl']
            return self.data[ihl * 4:]
        if item == 'option':
            ihl = self['ihl']
            return self.data[20:ihl * 4]
        if item == 'version':
            data = self["version+ihl"]
            return int.from_bytes(data, 'big') >> 4
        if item == 'ihl':
            data = self["version+ihl"]
            return int.from_bytes(data, 'big') & 0xf
        if item == 'r':
            data = int.from_bytes(self["r+df+mf+fo"], 'big')
            return data >> 15
        if item == 'df':
            data = int.from_bytes(self["r+df+mf+fo"], 'big')
            return (data >> 14) & 0x1
        if item == 'mf':
            data = int.from_bytes(self["r+df+mf+fo"], 'big')
            return (data >> 13) & 0x1
        if item == 'fo':
            data = int.from_bytes(self["r+df+mf+fo"], 'big')
            return (data & ((1 << 13) - 1)) * 8
        if item == 'prot_type':
            l, r = self.attr['prot_type']
            data = self.data[l:r]
            return "%04x" % int.from_bytes(self.data[l:r], byteorder='big')
        if item in self.attr:
            l, r = self.attr[item]
            return self.data[l:r]

    def __setitem__(self, key, value):
        if key == 'payload':
            ihl = self['ihl']
            self.data[ihl * 4:] = value

        if key in self.attr:
            l, r = self.attr[key]
            self.data[l:r] = value

    def add_payload(self, value):
        self.data += value

    def encode(self) -> bytearray:
        return self.data

    def decode(self, buf):
        self.data = buf

    def is_valid(self) -> bool:
        return True


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
        last = ipv4_packet["fo"] + len(ipv4_packet["payload"])

        if self.update_holes(key, first, last, ipv4_packet["mf"] != 0):
            heapq.heappush(self.reassemblers[key], (first, ipv4_packet))

        if self.counter[key] < len(self.holes[key]):
            return None
        _, packed_ipv4_packet = heapq.heappop(self.reassemblers[key])
        while self.reassemblers[key]:
            _, ipv4_packet = heapq.heappop(self.reassemblers[key])
            packed_ipv4_packet.add_payload(ipv4_packet["payload"])

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
        id = self.bytes_to_int(ipv4_packet["id"])
        prot_type = ipv4_packet["prot_type"]
        src_ip_addr = self.bytes_to_int(ipv4_packet["src_ip_addr"])
        dst_ip_addr = self.bytes_to_int(ipv4_packet["dst_ip_addr"])
        return id, prot_type, src_ip_addr, dst_ip_addr

    def bytes_to_int(self, bytes_packet):
        return int.from_bytes(bytes_packet, 'big')

    def cut(self, ipv4_packt: Ipv4PacketField) -> [Ipv4PacketField]:
        return []


class Ipv4:
    def __init__(self):
        self.ipv4_fragments = Ipv4Fragments()

    @staticmethod
    def prot_type():
        return "0800"

    def handle_packet(self, network: Network, packet: MetaPacket) -> None:
        packet.LOG_INFO("RECV")
        ipv4_packet = Ipv4PacketField()
        ipv4_packet.decode(packet.payload())
        if not ipv4_packet.is_valid():
            return

        ipv4_packet = self.ipv4_fragments.add_fragments(ipv4_packet)
        if ipv4_packet is None:
            return

        packet = MetaPacket(self.prot_type(), ipv4_packet["prot_type"], ipv4_packet["payload"])
        packet.set_ip_addr(ipv4_packet["src_ip_addr"])
        packet.LOG_INFO("SEND")
        packet.LOG_INFO("NETWORK SEND")
        network.write_packet(packet)

    def write_packet(self, network: Network, packet: MetaPacket) -> None:
        packet.LOG_INFO("RECV")
        ipv4_packet = Ipv4PacketField()

        for ipv4_packet in self.ipv4_fragments.cut(ipv4_packet):
            packet = MetaPacket(self.prot_type(), Ethernet.prot_type(), ipv4_packet.encode())
            network.write_link(packet)
