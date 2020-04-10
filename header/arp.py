import unpack

class Arp:
    def __init__(self, buf):
        self.hard_type = buf[:2]
        self.prot_type = buf[2:4]
        self.hard_size = buf[4:5]
        self.prot_size = buf[5:7]
        self.src_ethernet_addr = buf[7:13]
        self.src_ip_addr = buf[13:17]
        self.target_ethernet_addr = buf[17:23]
        self.target_ip_addr = buf[23:27]