import unpack


class Ethernet:
    def __init__(self, buf):
        self.src_addr = buf[:6]
        self.dst_addr = buf[6:12]
        self.type = buf[12:14]
        self.data = buf[14:]
