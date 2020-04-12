from link.tuntap import Tuntap
from link.link import Link
from header.ethernet import EthernetConfig
from stack.nic import Nic
from stack.stack import stack
import asyncio
import logging
logging.basicConfig(level=logging.INFO)

dev = Tuntap("tap0")
dev.active("192.168.1.0/24")
link_field = EthernetConfig(1500, dev.mac_addr())
link = Link(dev, link_field)
n = Nic(stack, link)


loop = asyncio.get_event_loop()
loop.run_forever()
