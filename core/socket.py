from core.sock import SockManager
from core import util


class Socket:
    def __init__(self, prot_type, local_ip_addr="", local_port=""):
        self._prot_type = prot_type
        self._local_port = local_port
        self._local_ip_addr = local_ip_addr
        self._local_ip_addr_int = util.ip_s2i(local_ip_addr)
        self._sock = SockManager.register_unidirectional_sock(prot_type, (self._local_ip_addr_int, self._local_port))
        self._state = None

    def listen(self):
        return self._sock.listen()

    async def accept(self):
        sock = await self._sock.accept()
        return sock

    def get_peer_name(self):
        src_ip_addr = self._sock.src_ip_addr
        src_port = self._sock.src_port
        return src_ip_addr, src_port

    async def read(self):
        buf = await self._sock.read()
        return buf

    def write(self, data):
        return self._sock.write(data)

    def connect(self, remote_info):
        self._sock.connect(remote_info)
