from pytun import TunTapDevice
import pytun
import os


class Tuntap:
    def __init__(self, dev_name: str, is_tap: bool = True) -> None:
        self.dev_name = dev_name
        self.is_tap = is_tap
        self.dev = None

    def new_net_dev(self) -> None:
        flags = pytun.IFF_TAP if self.is_tap else pytun.IFF_TUN
        flags |= pytun.IFF_NO_PI
        self.dev = pytun.TunTapDevice(self.dev_name, flags)

    def set_link_up(self) -> None:
        os.system("ip link set " + self.dev_name + " up")

    def set_route(self, cidr: str) -> None:
        os.system("ip route add " + cidr + " dev " + self.dev_name)

    def add_ip(self, ip: str) -> None:
        os.system("ip addr add " + ip + " dev " + self.dev_name)

    def mac_addr(self) -> bytes:
        return self.dev.hwaddr

    def no_blocking_read(self, size: int) -> bytearray:
        return self.dev.read(size)

    def mut(self) -> int:
        return self.dev.mtu

    def blocking_read(self, size: int) -> bytearray:
        while True:
            tmp = self.dev.read(size)
            if tmp:
                yield tmp

    def no_blocking_write(self, data: bytearray) -> None:
        pass
