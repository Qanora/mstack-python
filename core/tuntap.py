import pytun
import os
import asyncio
from core import util
from header.Ethernet import Ethernet


class Tuntap:
    def __init__(self, dev_name: str, ip_addr: str, route: str, queue_mx_size=500, is_tap: bool = True) -> None:
        self._dev_name = dev_name
        self._is_tap = is_tap
        self._dev = self._new_net_dev()
        self._running = True
        self._ip_addr = ip_addr
        self._route = route
        self._set_link_up()
        self._set_route(route)
        self._queue_mx_size = queue_mx_size
        self._rx_queue = asyncio.Queue(self._queue_mx_size)
        self._tx_queue = asyncio.Queue(self._queue_mx_size)
        self._loop = asyncio.get_event_loop()

    def active(self):
        self.add_callback()
        self._loop.create_task(self.rx_loop())

    def _new_net_dev(self):
        flags = pytun.IFF_TAP if self._is_tap else pytun.IFF_TUN
        flags |= pytun.IFF_NO_PI
        return pytun.TunTapDevice(self._dev_name, flags)

    def _set_link_up(self) -> None:
        os.system("ip link set " + self._dev_name + " up")

    def _set_route(self, cidr: str) -> None:
        os.system("ip route add " + cidr + " dev " + self._dev_name)

    def _set_ip(self, ip: str) -> None:
        os.system("ip addr add " + ip + " dev " + self._dev_name)

    @property
    def ip_addr(self) -> int:
        return util.ip_s2i(self._ip_addr)

    @property
    def mac_addr(self) -> int:
        return util.mac_b2i(self._dev.hwaddr)

    @property
    def mtu(self) -> int:
        return self._dev.mtu

    def no_blocking_read(self, size: int) -> bytearray:
        return self._dev.read(size)

    def no_blocking_write(self, data: bytearray) -> None:
        self._dev.write(bytes(data))

    def transmit(self, packet):
        self._tx_queue.put_nowait(packet)

    def receive(self, packet):
        Ethernet.recv(packet)

    async def rx_loop(self):
        while self._running:
            packet = await self._rx_queue.get()
            if packet:
                self.receive(packet)

    def add_callback(self):

        def enqueue_packet_wrap():
            buf = self.no_blocking_read(self.mtu)
            if buf:
                self._rx_queue.put_nowait(buf)

        def dequeue_packet_wrap():
            try:
                buf = self._tx_queue.get_nowait()
                self.no_blocking_write(buf)
            except asyncio.QueueEmpty:
                pass

        self._loop.add_writer(self._dev.fileno(), dequeue_packet_wrap)
        self._loop.add_reader(self._dev.fileno(), enqueue_packet_wrap)