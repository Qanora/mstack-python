import asyncio
from header.udp import Udp
from header.tcp import Tcp
import logging
from core import util


class Sock:
    def __init__(self, prot_type, remote_info, local_info, queue_mx_size=500):
        self._prot_type = prot_type
        self._enable = False
        self._state = "NOT INIT"
        self._local_ip_addr, self._local_port = local_info
        if remote_info:
            self._remote_ip_addr, self._remote_port = remote_info
        else:
            self._remote_ip_addr = None
            self._remote_port = None
        self._queue_mx_size = queue_mx_size
        self._rx_queue = asyncio.Queue(self._queue_mx_size)
        self._tx_queue = asyncio.Queue(self._queue_mx_size)
        self._accept_queue = asyncio.Queue(self._queue_mx_size)
        self._seq = 0
        self._ack = 0
        self._option_bin = None
        self._option = None

    def LOG(self, info, status):
        log = getattr(logging, info)
        remote_ip_addr, remote_port = "None", "None"
        if self.remote_ip_addr is not None:
            remote_ip_addr = util.ip_i2s(self.remote_ip_addr)
        if self.remote_port is not None:
            remote_port = str(self.remote_port)
        local_ip_addr, local_port = util.ip_i2s(self.local_ip_addr), str(self.local_port)
        options_str = "NO OPTION"
        if self.option is not None:
            options_str = " ".join([v.name for k, v in self.option.items()])
        log("[SOCK %s %s] (%s:%s -> %s:%s) %s %s %s", status, self.state, remote_ip_addr, remote_port, local_ip_addr,
            local_port, self._seq, self._ack, options_str)

    @property
    def option(self):
        return self._option

    @option.setter
    def option(self, value):
        self._option = value

    @property
    def option_bin(self):
        return self._option_bin

    @option_bin.setter
    def option_bin(self, value):
        self._option_bin = value

    @property
    def seq(self):
        return self._seq

    @seq.setter
    def seq(self, value):
        self._seq = value

    @property
    def ack(self):
        return self._ack

    @ack.setter
    def ack(self, value):
        self._ack = value

    @property
    def tx_queue_size(self):
        return self._tx_queue.qsize()

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, value):
        self._state = value

    @property
    def prot_type(self):
        return self._prot_type

    @property
    def remote_port(self):
        return self._remote_port

    @property
    def remote_ip_addr(self):
        return self._remote_ip_addr

    @property
    def local_port(self):
        return self._local_port

    @property
    def local_ip_addr(self):
        return self._local_ip_addr

    def listen(self):
        self._state = "TCP_LISTEN"
        self._enable = True

    async def connect(self):
        remote_info = self.remote_ip_addr, self.remote_port
        local_info = self.local_ip_addr, self.local_port

        # TODO generate seq
        # TODO add option
        Tcp.tcp_send_syn(bytearray(0), remote_info, local_info)
        self._state = "TCP_SYN_SENT"

        while self._state != "TCP_ESTABLISHED":
            await asyncio.sleep(0.5)
        self._enable = True

    async def accept(self):
        sock = await self._accept_queue.get()
        return sock

    async def read(self):
        data = await self._rx_queue.get()
        self._rx_queue.task_done()
        return data

    def write(self, data):
        self._tx_queue.put_nowait(data)

    def enqueue_data(self, data):
        self._rx_queue.put_nowait(data)

    def dequeue_data(self):
        try:
            return self._tx_queue.get_nowait()
        except asyncio.QueueEmpty:
            pass

    def enqueue_acceptor(self, sock):
        self._accept_queue.put_nowait(sock)

    def close(self):
        remote_info = self.remote_ip_addr, self.remote_port
        local_info = self.local_ip_addr, self.local_port
        Tcp.tcp_send_fin(bytearray(0), remote_info, local_info)
        self.state = "TCP_FIN_WAIT_1"
        self.LOG("info", "closing now")



class SockManager:
    _unidirectional_sock_map = {Udp.PROT_TYPE: {}, Tcp.PROT_TYPE: {}}
    _bidirectional_sock_map = {Udp.PROT_TYPE: {}, Tcp.PROT_TYPE: {}}

    @classmethod
    def init(cls):
        loop = asyncio.get_event_loop()
        loop.create_task(SockManager.tx_loop())

    @classmethod
    def register_unidirectional_sock(cls, prot_type, local_info):
        sock = Sock(prot_type, None, local_info)
        SockManager._unidirectional_sock_map[prot_type][local_info] = sock
        return sock

    @classmethod
    def lookup_unidirectional_sock(cls, prot_type, local_info):
        if local_info in SockManager._unidirectional_sock_map[prot_type]:
            return SockManager._unidirectional_sock_map[prot_type][local_info]
        return None

    @classmethod
    def register_bidirectional_sock(cls, prot_type, remote_info, local_info):
        sock = Sock(prot_type, remote_info, local_info)
        if local_info not in SockManager._bidirectional_sock_map[prot_type]:
            SockManager._bidirectional_sock_map[prot_type][local_info] = []
        SockManager._bidirectional_sock_map[prot_type][local_info].append(sock)
        return sock

    @classmethod
    def lookup_bidirectional_sock(cls, prot_type, local_info, remote_info):
        remote_ip_addr, remote_port = remote_info
        if local_info not in SockManager._bidirectional_sock_map[prot_type]:
            return None
        for sock in SockManager._bidirectional_sock_map[prot_type][local_info]:
            if sock.remote_ip_addr == remote_ip_addr and sock.remote_port == remote_port:
                return sock
        return None

    @classmethod
    async def tx_loop(cls):
        while True:
            await asyncio.sleep(0.5)
            for prot_type, socks in SockManager._unidirectional_sock_map.items():
                for local_info, sock in socks.items():
                    buf = sock.dequeue_data()
                    if buf:
                        if prot_type == Udp.PROT_TYPE:
                            Udp.write(buf, (sock.remote_ip_addr, sock.remote_port), local_info)
                        if prot_type == Tcp.PROT_TYPE:
                            Tcp.write(buf, (sock.remote_ip_addr, sock.remote_port), local_info)

            for prot_type, socks in SockManager._bidirectional_sock_map.items():
                for local_info, socks in socks.items():
                    for sock in socks:
                        buf = sock.dequeue_data()
                        if buf:
                            if prot_type == Udp.PROT_TYPE:
                                Udp.write(buf, (sock.remote_ip_addr, sock.remote_port), local_info)
                            if prot_type == Tcp.PROT_TYPE:
                                Tcp.write(buf, (sock.remote_ip_addr, sock.remote_port), local_info)