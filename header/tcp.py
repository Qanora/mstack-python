from header import Protocol

class Tcp(Protocol):
    PROT_TYPE = 0x06

    @classmethod
    def recv(cls, packet):
        pass

    @classmethod
    def write(cls, packet, src_info, dst_info):
        pass