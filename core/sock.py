import asyncio
from header.udp import Udp
from header.tcp import Tcp


class Sock:
    def __init__(self, prot_type, remote_info, local_info, queue_mx_size=500):
        self._prot_type = prot_type
        self._enable = False
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
        self._enable = True

    def connect(self, remote_info):
        remote_ip_addr, remote_port = remote_info
        self._remote_ip_addr = remote_ip_addr
        self._remote_port = remote_port

    def accept(self):
        sock = self._accept_queue.get_nowait()
        sock._enable = True
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


class SockManager:
    _sock_map = {}
    _sock_map[Udp.PROT_TYPE] = {}
    _sock_map[Tcp.PROT_TYPE] = {}
    @classmethod
    def init(cls):
        loop = asyncio.get_event_loop()
        loop.create_task(SockManager.tx_loop())

    @classmethod
    def lookup_sock(cls, prot_type, remote_info, local_info):
        remote_ip_addr, remote_port = remote_info
        if local_info in SockManager._sock_map[prot_type]:
            return SockManager._sock_map[prot_type][local_info]
        return None

    @classmethod
    def register_sock(cls, prot_type, local_info):
        # TODO build sock
        if prot_type == Udp.PROT_TYPE:
            sock = Sock(prot_type, None, local_info)
            SockManager._sock_map[prot_type][local_info] = sock
            return sock

    @classmethod
    async def tx_loop(cls):
        while True:
            await asyncio.sleep(0.5)
            for prot_type, socks in SockManager._sock_map.items():
                for local_info, sock in socks.items():
                    buf = sock.dequeue_data()
                    if buf:
                        if prot_type == Tcp.PROT_TYPE:
                            Tcp.write(buf, (sock.remote_ip_addr, sock.remote_port), local_info)
                        if prot_type == Udp.PROT_TYPE:
                            Udp.write(buf, (sock.remote_ip_addr, sock.remote_port), local_info)
