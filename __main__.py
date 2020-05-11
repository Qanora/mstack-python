import logging

from core.netdev import NetDevManager
from core.tuntap import Tuntap
from core.sock import SockManager
from core.socket import Socket
from header.udp import Udp
import asyncio
logging.basicConfig(level=logging.INFO)
route_addr = "192.168.1.0/24"
ip_addr = "192.168.1.1"
tap_name = "tap0"


def init_net_dev(route_addr, ip_addr, tap_name):
    tap = Tuntap(tap_name, ip_addr, route_addr)

    NetDevManager.register_net_dev(tap)
    SockManager.init()


init_net_dev(route_addr, ip_addr, tap_name)


async def udp_test():
    socket = Socket(Udp.PROT_TYPE, "192.168.1.1", 30000)
    while True:
        buf = await socket.read()
        socket.write(buf)
        print("get", buf)

loop = asyncio.get_event_loop()
loop.create_task(udp_test())

loop.run_forever()
