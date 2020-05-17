from core.sock import SockManager
from core import util


class Socket:
    def __init__(self, prot_type, local_ip_addr="", local_port=""):
        self._prot_type = prot_type
        self._local_port = local_port
        self._local_ip_addr = local_ip_addr
        self._local_ip_addr_int = util.ip_s2i(local_ip_addr)
        self._sock = None
        self._state = None

    def listen(self):
        self._sock = SockManager.register_unidirectional_sock(self._prot_type,
                                                              (self._local_ip_addr_int, self._local_port))
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

    async def connect(self, remote_info):
        if self._sock is not None:
            return
        remote_ip_addr, remote_port = remote_info
        remote_ip_addr = util.ip_s2i(remote_ip_addr)

        remote_info_int = remote_ip_addr, remote_port
        local_info_int = self._local_ip_addr_int, self._local_port

        self._sock = SockManager.lookup_bidirectional_sock(self._prot_type, local_info_int, remote_info_int)
        await self._sock.connect()
        return

    def close(self):
        self._sock.close()
