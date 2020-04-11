from link.tuntap import Tuntap
from link.link import Link
from header.ethernet import EthernetConfig
from stack.nic import Nic


def parpare_tuntap() -> Tuntap:
    tap_name = "tap0"
    dev = Tuntap(tap_name)
    dev.new_net_dev()
    dev.set_link_up()
    dev.set_route("192.168.1.0/24")
    print("start capturing")
    return dev


fd = parpare_tuntap()
link_field = EthernetConfig(1500, fd.mac_addr())
link = Link(fd, link_field)
n = Nic()
link.attach(n)
