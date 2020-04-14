from link.tuntap import Tuntap
from link.link import Link
from header.ethernet import EthernetConfig
from stack.nic import Nic
from stack.stack import stack
import asyncio
import logging
from header.arp import ArpConfig, Arp
import ipaddress

logging.basicConfig(level=logging.INFO)
route_addr = "192.168.1.0/24"
ip_addr = "192.168.1.1"

dev = Tuntap("tap0")
dev.active(route_addr)
link_field = EthernetConfig(1500, dev.mac_addr())
link = Link(dev, link_field)

arp_config = ArpConfig()
arp_config.ip_addr = ipaddress.ip_address(ip_addr).packed
arp_config.mac_addr = dev.mac_addr()

stack.register_link(link)
stack.register_network(Arp(arp_config))
n = Nic(stack, link)


loop = asyncio.get_event_loop()
loop.run_forever()
