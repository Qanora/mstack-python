from demux.demux import Demux
from demux.udpdev import UdpDev
from dev.tuntap import Tuntap
from dev.dev import Dev
from link.ethernet import Ethernet
from stack.stack import Stack
import asyncio
import logging
from link.arp import Arp
import ipaddress
from link.link import Link
from network.network import Network
from network.ipv4 import Ipv4
from network.icmp import ICMP
from transport.transport import Transport
from transport.udp import Udp
import util
FORMAT = "%(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)

route_addr = "192.168.1.0/24"
ip_addr = "192.168.1.1"

stack = Stack()
# set device
tap = Tuntap("tap0")
tap.active(route_addr)

ip_addr = ipaddress.ip_address(ip_addr).packed
dev = Dev(tap, int.from_bytes(ip_addr, 'big'))

stack.set_dev(dev)
logging.info("[MYMAC] " + util.mac_i2s(stack.my_mac_addr()))
logging.info("[MYIP] " + util.ip_i2s(stack.my_ip_addr()))

# set link
link = Link(stack)
stack.set_link_layer(link)
stack.register_link_protocol(dev)


ethernet = Ethernet()
stack.register_link_protocol(ethernet)

# set arp
arp = Arp()
stack.register_link_protocol(arp)

network = Network(stack)
stack.set_network_layer(network)

ipv4 = Ipv4()
stack.register_network_protocol(ipv4)

icmp = ICMP()
stack.register_network_protocol(icmp)


transport = Transport(stack)
stack.set_transport_layer(transport)

udp = Udp()
stack.register_transport_protocol(udp)

demux = Demux(stack)
stack.set_demux_layer(demux)

udp_dev = UdpDev()
stack.register_demux_dev(udp_dev)

udp_endpoint = stack.new_endpoint(UdpDev.prot_type())

udp_endpoint.bind(ip_addr="192.168.1.1", port=30000)

loop = asyncio.get_event_loop()

async def print_packet():
    while True:
        buf = await udp_endpoint.read()
        print("GET PACKET:", buf)

loop.create_task(print_packet())

stack.attch()
loop.run_forever()

