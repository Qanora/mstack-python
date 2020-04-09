import pytun
import os


class Tuntap:
    def __init__(self, dev_name, is_tap=True):
        self.dev_name = dev_name
        self.is_tap = is_tap
        self.dev = None

    def new_net_dev(self):
        flags = pytun.IFF_TAP if self.is_tap else pytun.IFF_TUN
        flags |= pytun.IFF_NO_PI
        self.dev = pytun.TunTapDevice(self.dev_name, flags)

    def set_link_up(self):
        os.system("ip link set " + self.dev_name + " up")

    def set_route(self, cidr):
        os.system("ip route add " + cidr + " dev " + self.dev_name)

    def add_ip(self, ip):
        os.system("ip addr add " + ip + " dev " + self.dev_name)

    def no_blocking_read(self, size):
        return self.dev.read(size)

    def mut(self):
        return self.dev.mtu