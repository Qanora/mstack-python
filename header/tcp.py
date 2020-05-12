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
        (TypeLen.L2, "length")
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

    @property
    def length(self):
        return self.flags >> 11

    @length.setter
    def length(self, value):
        self.flags = (value << 11) + (self.flags & ((1 << 11) - 1))

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
        log("[TCP %s] (%d -> %d) seq: %d, ack: %d, flags: %s", status, self.src_port, self.dst_port,
            self.seq_no, self.ack_no, bin(self.flags)[2:][11:])


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
        Tcp.tcp_state_transform(sock, ipv4_packet, tcp_packet)

    @classmethod
    def tcp_state_transform(cls, sock, ipv4_packet, tcp_packet):
        if sock.state == "TCP_CLOSE":
            Tcp.tcp_close(sock, ipv4_packet, tcp_packet)
            return
        if sock.state == "TCP_LISTEN":
            tcp_packet.LOG("info", "LISTEN TAKE")
            Tcp.tcp_listen(sock, ipv4_packet, tcp_packet)
            return
        if sock.state == "TCP_SYN_SENT":
            Tcp.tcp_synsent(sock, ipv4_packet, tcp_packet)
            return

        # first check sequence number
        if not Tcp.tcp_verify_segement(sock, ipv4_packet, tcp_packet):
            if tcp_packet.rst:
                Tcp.tcp_send_ack(sock, ipv4_packet, tcp_packet)
            return

        # second check the RST bit
        if tcp_packet.rst:
            pass

        # third check security and precedence

        # fourth check the SYN bit
        if tcp_packet.syn:
            Tcp.tcp_send_challenge_ack(sock, ipv4_packet, tcp_packet)
            return

        # fifth check the ACK field
        if not tcp_packet.ack:
            return

        # ACK bit is ON
        if sock.state == "TCP_SYN_RECEIVED":
            # -> TCP_ESTABLISHED
            pass


        # UNKNOWN
        if sock.state in ["TCP_ESTABLISHED", "TCP_FIN_WAIT_1", "TCP_FIN_WAIT_2", "TCP_CLOSE_WAIT"
                          "TCO_CLOSING", "TCP_LAST_ACK"]:
            pass

        if sock.tx_queue_size() == 0:
            if sock.state == "TCP_FIN_WAIT_1":
                # -> TCP_FIN_WAIT_2
                pass
            if sock.state == "TCP_FIN_WAIT_2":
                pass
            if sock.state == "TCP_CLOSING":
                # -> TCP_TIME_WAIT
                pass
            if sock.state == "TCP_LAST_ACK":
                # -> CLOSED
                pass
            if sock.state == "TCP_TIME_WAIT":
                pass

        # sixth, check the URG bit
        if tcp_packet.urg:
            pass

        # seven, process the segment txt
        if sock.state in ["TCP_ESTABLISHED", "TCP_FIN_WAIT_1", "TCP_FIN_WAIT_2"]:
            pass

        # eighth, check the FIN bit
        if sock.state in ["TCP_CLOSE_WAIT", "TCP_CLOSING", "TCP_LAST_ACK", "TCP_TIME_WAIT"]:
            pass

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
        sock.seq += 1
        reply_tcp_pack.ack_no = tcp_packet.seq_no + 1
        reply_tcp_pack.window_size = tcp_packet.window_size
        reply_tcp_pack.urgent_pointer = 0x0000
        reply_tcp_pack.option = 0x00000000
        reply_tcp_pack.checksum = 0x0000
        reply_tcp_pack.length = len(reply_tcp_pack.buffer)
        reply_tcp_pack.payload = tcp_packet.payload
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
        sock.seq += 1
        reply_tcp_pack.ack_no = tcp_packet.seq_no + 1
        reply_tcp_pack.window_size = tcp_packet.window_size
        reply_tcp_pack.urgent_pointer = 0x0000
        reply_tcp_pack.option = 0x00000000
        reply_tcp_pack.checksum = 0x0000
        reply_tcp_pack.length = len(reply_tcp_pack.buffer)
        reply_tcp_pack.payload = tcp_packet.payload
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
            tcp_packet.LOG("info", "LISTEN TAKE")
            sock.state = "TCP_SYN_RCVD"
            Tcp.tcp_send_syn_ack(sock, ipv4_packet, tcp_packet)
        return
    @classmethod
    def tcp_synsent(cls, sock, ipv4_packet, tcp_packet):
        pass

    @classmethod
    def write(cls, packet, src_info, dst_info):
        pass
