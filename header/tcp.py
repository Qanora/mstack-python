from header import Protocol
from header import Structure, TypeLen
import logging
from core import util


class FakeHead(Structure):
    _fields_ = [
        (TypeLen.L4, "src_ip_addr"),
        (TypeLen.L4, "dst_ip_addr"),
        (TypeLen.L1, "NULL"),
        (TypeLen.L1, "prot_type"),
        (TypeLen.L2, "length"),
    ]

class TcpPacket(Structure):
    _fields_ = [
        (TypeLen.L2, "src_port"),
        (TypeLen.L2, "dst_port"),
        (TypeLen.L4, "seq_no"),
        (TypeLen.L4, "ack_no"),
        (TypeLen.L2, "flags"),
        (TypeLen.L2, "window_size"),
        (TypeLen.L2, "checksum"),
        (TypeLen.L2, "urgent_pointer"),
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        option_length = self.length - len(self.header)
        if option_length >= 0:
            self.option = self.payload[:option_length]
            self.payload = self.payload[option_length:]
        else:
            self.option = bytearray(0)
            self.payload = bytearray(0)


    @property
    def buffer(self):
        return self.header + self.option + self.payload

    @property
    def length(self):
        return (self.flags >> 12) * 4

    @length.setter
    def length(self, value):
        value = value // 4
        self.flags = (value << 12) + (self.flags & ((1 << 12) - 1))

    @property
    def ack(self):
        return (self.flags >> 4) & 1

    @ack.setter
    def ack(self, value):
        if value == 1:
            self.flags = self.flags | (1 << 4)
        if value == 0:
            self.flags = self.flags & (~(1 << 4))

    @property
    def psh(self):
        return (self.flags >> 3) & 1

    @psh.setter
    def psh(self, value):
        if value == 1:
            self.flags = self.flags | (1 << 3)
        if value == 0:
            self.flags = self.flags & (~(1 << 3))

    @property
    def rst(self):
        return (self.flags >> 2) & 1

    @rst.setter
    def rst(self, value):
        if value == 1:
            self.flags = self.flags | (1 << 2)
        if value == 0:
            self.flags = self.flags & (~(1 << 2))

    @property
    def syn(self):
        return (self.flags >> 1) & 1

    @syn.setter
    def syn(self, value):
        if value == 1:
            self.flags = self.flags | (1 << 1)
        if value == 0:
            self.flags = self.flags & (~(1 << 1))

    @property
    def fin(self):
        return self.flags & 1

    @fin.setter
    def fin(self, value):
        if value == 1:
            self.flags = self.flags | 1
        if value == 0:
            self.flags = self.flags & (~1)

    def LOG(self, level, status):
        log = getattr(logging, level)
        log("[TCP %s] (%d -> %d) seq: %d, ack: %d, flags: %s - %d %d %d %d", status, self.src_port, self.dst_port,
            self.seq_no, self.ack_no, bin(self.flags)[2:][11:], len(self.header), len(self.option), len(self.payload), self.length)


class Tcp(Protocol):
    PROT_TYPE = 0x06

    @classmethod
    def recv(cls, ipv4_packet):
        tcp_packet = TcpPacket(ipv4_packet.payload)
        tcp_packet.LOG("info", "TAKE")
        from core.sock import SockManager
        local_info = ipv4_packet.dst_ip_addr, tcp_packet.dst_port
        remote_info = ipv4_packet.src_ip_addr, tcp_packet.src_port
        sock = SockManager.lookup_bidirectional_sock(Tcp.PROT_TYPE, local_info, remote_info)
        if sock is None:
            sock = SockManager.lookup_unidirectional_sock(Tcp.PROT_TYPE, local_info)
            if sock is None:
                tcp_packet.LOG("error", "no sock")
                return
            sock = SockManager.register_bidirectional_sock(Tcp.PROT_TYPE, remote_info, local_info)
            sock.state = "TCP_LISTEN"
        sock.LOG("info", "START")
        Tcp.tcp_state_transform(sock, ipv4_packet, tcp_packet)
        sock.LOG("info", "FINISH")

    @classmethod
    def tcp_state_transform(cls, sock, ipv4_packet, tcp_packet):
        sock.seq = max(sock.seq, tcp_packet.ack_no)

        if tcp_packet.syn == 1:
            sock.ack = max(sock.ack, tcp_packet.seq_no + max(1, len(tcp_packet.payload)))

        if tcp_packet.psh == 1 and tcp_packet.ack == 1:
            sock.ack = max(sock.ack, tcp_packet.seq_no + max(1, len(tcp_packet.payload)))

        if sock.state == "TCP_CLOSE":
            Tcp.tcp_close(sock, ipv4_packet, tcp_packet)
            return
        if sock.state == "TCP_LISTEN":
            Tcp.tcp_listen(sock, ipv4_packet, tcp_packet)
            return
        if sock.state == "TCP_SYN_SENT":
            Tcp.tcp_synsent(sock, ipv4_packet, tcp_packet)
            return

        # first check sequence number
        # if not Tcp.tcp_verify_segement(sock, ipv4_packet, tcp_packet):
        #     if tcp_packet.rst:
        #         Tcp.tcp_send_ack(sock, ipv4_packet, tcp_packet)
        #     return

        # second check the RST bit
        # if tcp_packet.rst:
        #     pass

        # third check security and precedence

        # fourth check the SYN bit
        # if tcp_packet.syn:
        #     Tcp.tcp_send_challenge_ack(sock, ipv4_packet, tcp_packet)
        #     return

        # fifth check the ACK field
        # if not tcp_packet.ack:
        #     return

        # ACK bit is ON
        if sock.state == "TCP_SYN_RECV":
            # -> TCP_ESTABLISHED
            tcp_packet.LOG("info", "TCP_SYN_RECV -> TCP_ESTABLISHED")
            sock.state = "TCP_ESTABLISHED"
            from core.sock import SockManager
            local_info = sock.local_ip_addr, sock.local_port
            base_sock = SockManager.lookup_unidirectional_sock(Tcp.PROT_TYPE, local_info)
            base_sock.enqueue_acceptor(sock)
            return


        # UNKNOWN
        # if sock.state in ["TCP_ESTABLISHED", "TCP_FIN_WAIT_1", "TCP_FIN_WAIT_2", "TCP_CLOSE_WAIT"
        #                   "TCO_CLOSING", "TCP_LAST_ACK"]:
        #     pass

        # if sock.tx_queue_size() == 0:
        #     if sock.state == "TCP_FIN_WAIT_1":
        #         # -> TCP_FIN_WAIT_2
        #         pass
        #     if sock.state == "TCP_FIN_WAIT_2":
        #         pass
        #     if sock.state == "TCP_CLOSING":
        #         # -> TCP_TIME_WAIT
        #         pass
        #     if sock.state == "TCP_LAST_ACK":
        #         # -> CLOSED
        #         pass
        #     if sock.state == "TCP_TIME_WAIT":
        #         pass

        # sixth, check the URG bit
        # if tcp_packet.urg:
        #     pass

        # seven, process the segment txt
        if sock.state in ["TCP_ESTABLISHED", "TCP_FIN_WAIT_1", "TCP_FIN_WAIT_2"]:
            if tcp_packet.psh == 1:
                sock.enqueue_data(tcp_packet.payload)
                Tcp.tcp_send_ack(sock, ipv4_packet, tcp_packet)


        # eighth, check the FIN bit
        # if sock.state in ["TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK", "TCP_TIME_WAIT"]:
        #     pass

        # congestion control and delacks

    @classmethod
    def tcp_send_challenge_ack(cls, sock, ipv4_packet, tcp_packet):
        pass

    @classmethod
    def tcp_send_syn_ack(cls, sock, ipv4_packet, tcp_packet):
        reply_tcp_pack = TcpPacket()

        reply_tcp_pack.ack = 1
        reply_tcp_pack.syn = 1

        reply_tcp_pack.src_port = tcp_packet.dst_port
        reply_tcp_pack.dst_port = tcp_packet.src_port

        reply_tcp_pack.seq_no = sock.seq
        reply_tcp_pack.ack_no = sock.ack

        reply_tcp_pack.window_size = tcp_packet.window_size
        reply_tcp_pack.urgent_pointer = 0x0000

        # reply_tcp_pack.option = tcp_packet.option

        sock.option = tcp_packet.option

        reply_tcp_pack.checksum = 0x0000
        reply_tcp_pack.length = len(reply_tcp_pack.header) + len(reply_tcp_pack.option)
        reply_tcp_pack.LOG("info", "OUT")
        fake_head = FakeHead()
        fake_head.src_ip_addr = ipv4_packet.dst_ip_addr
        fake_head.dst_ip_addr = ipv4_packet.src_ip_addr
        fake_head.prot_type = Tcp.PROT_TYPE
        fake_head.length = len(reply_tcp_pack.buffer)

        reply_tcp_pack.checksum = util.checksum(fake_head.buffer + reply_tcp_pack.buffer)
        from header.ipv4 import Ipv4, Ipv4Packet
        reply_ipv4_packet = Ipv4Packet()
        reply_ipv4_packet.src_ip_addr = ipv4_packet.dst_ip_addr
        reply_ipv4_packet.dst_ip_addr = ipv4_packet.src_ip_addr
        reply_ipv4_packet.payload = reply_tcp_pack.buffer

        Ipv4.write(reply_ipv4_packet, Tcp.PROT_TYPE)

    @classmethod
    def tcp_send_ack(cls, sock, ipv4_packet, tcp_packet):
        reply_tcp_pack = TcpPacket()

        reply_tcp_pack.ack = 1

        reply_tcp_pack.src_port = tcp_packet.dst_port
        reply_tcp_pack.dst_port = tcp_packet.src_port

        reply_tcp_pack.seq_no = sock.seq
        reply_tcp_pack.ack_no = sock.ack

        reply_tcp_pack.window_size = tcp_packet.window_size

        reply_tcp_pack.urgent_pointer = 0x0000
        reply_tcp_pack.option = tcp_packet.option

        reply_tcp_pack.checksum = 0x0000
        reply_tcp_pack.length = len(reply_tcp_pack.header) + len(reply_tcp_pack.option)

        reply_tcp_pack.LOG("info", "OUT")

        fake_head = FakeHead()
        fake_head.src_ip_addr = ipv4_packet.dst_ip_addr
        fake_head.dst_ip_addr = ipv4_packet.src_ip_addr
        fake_head.prot_type = Tcp.PROT_TYPE
        fake_head.length = len(reply_tcp_pack.buffer)

        reply_tcp_pack.checksum = util.checksum(fake_head.buffer + reply_tcp_pack.buffer)

        from header.ipv4 import Ipv4, Ipv4Packet
        reply_ipv4_packet = Ipv4Packet()
        reply_ipv4_packet.src_ip_addr = ipv4_packet.dst_ip_addr
        reply_ipv4_packet.dst_ip_addr = ipv4_packet.src_ip_addr
        reply_ipv4_packet.payload = reply_tcp_pack.buffer

        Ipv4.write(reply_ipv4_packet, Tcp.PROT_TYPE)

    @classmethod
    def tcp_verify_segement(cls, sock, ipv4_packet, tcp_packet):
        pass

    @classmethod
    def tcp_close(cls, sock, ipv4_packet, tcp_packet):
        pass

    @classmethod
    def tcp_listen(cls, sock, ipv4_packet, tcp_packet):
        if tcp_packet.syn == 1:
            tcp_packet.LOG("info", "TCP_LISTEN -> TCP_SYN_RECV")
            Tcp.tcp_send_syn_ack(sock, ipv4_packet, tcp_packet)
            sock.state = "TCP_SYN_RECV"
        return

    @classmethod
    def tcp_synsent(cls, sock, ipv4_packet, tcp_packet):
        pass

    @classmethod
    def tcp_send_data(cls, packet, remote_info, local_info):
        from core.sock import SockManager
        sock = SockManager.lookup_bidirectional_sock(Tcp.PROT_TYPE, local_info, remote_info)
        if sock is None:
            return
        src_ip_addr, src_port = local_info
        dst_ip_addr, dst_port = remote_info

        tcp_packet = TcpPacket()

        tcp_packet.src_port = src_port
        tcp_packet.dst_port = dst_port

        tcp_packet.ack_no = sock.ack
        tcp_packet.seq_no = sock.seq

        tcp_packet.psh = 1
        tcp_packet.ack = 1

        tcp_packet.window_size = 0x18eb

        tcp_packet.payload = packet

        tcp_packet.urgent_pointer = 0x0000

        tcp_packet.checksum = 0x0000

        # tcp_packet.option = sock.option

        tcp_packet.length = len(tcp_packet.header) + len(tcp_packet.option)

        tcp_packet.LOG("info", "OUT")

        fake_head = FakeHead()
        fake_head.src_ip_addr = src_ip_addr
        fake_head.dst_ip_addr = dst_ip_addr
        fake_head.prot_type = Tcp.PROT_TYPE
        fake_head.length = len(tcp_packet.buffer)

        tcp_packet.checksum = util.checksum(fake_head.buffer + tcp_packet.buffer)

        from header.ipv4 import Ipv4, Ipv4Packet
        ipv4_packet = Ipv4Packet()
        ipv4_packet.src_ip_addr = src_ip_addr
        ipv4_packet.dst_ip_addr = dst_ip_addr
        ipv4_packet.payload = tcp_packet.buffer
        ipv4_packet.LOG("info", "OUT")
        Ipv4.write(ipv4_packet, Tcp.PROT_TYPE)

    @classmethod
    def write(cls, packet, remote_info, local_info):
        Tcp.tcp_send_data(packet, remote_info, local_info)

