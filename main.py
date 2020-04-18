from dev.tuntap import Tuntap
from dev.dev import Dev
from header.ethernet import Ethernet
from stack.stack import Stack
import asyncio
import logging
from header.arp import Arp
import ipaddress
from link.link import Link
from network.network import Network
from header.ipv4 import Ipv4
from header.icmp import ICMP
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

stack.attch()

loop = asyncio.get_event_loop()
loop.run_forever()
