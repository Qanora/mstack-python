#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import util


class MetaPacket:
    _seq = 0

    def __init__(self, _sender_prot_type: int, _target_prot_type: int, _payload):
        MetaPacket._seq += 1
        self._sender_prot_type = _sender_prot_type
        self._target_prot_type = _target_prot_type
        self._payload = _payload
        self._mac_addr = None
        self._ip_addr = None
        self._port = None
        self._status = "IN"

    def seq(self):
        return MetaPacket._seq

    @property
    def state(self):
        return self._status

    @state.setter
    def state(self, value):
        self._status = value

    @property
    def sender_prot_type(self) -> int:
        return self._sender_prot_type

    @sender_prot_type.setter
    def sender_prot_type(self, value):
        self._sender_prot_type = value

    @property
    def target_prot_type(self) -> int:
        return self._target_prot_type

    @target_prot_type.setter
    def target_prot_type(self, value):
        self._target_prot_type = value

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, value):
        self._payload = value

    @property
    def ip_addr(self) -> int:
        return self._ip_addr

    @ip_addr.setter
    def ip_addr(self, value):
        self._ip_addr = value

    @property
    def mac_addr(self) -> int:
        return self._mac_addr

    @mac_addr.setter
    def mac_addr(self, value):
        self._mac_addr = value

    @property
    def port(self):
        return self._port
    @port.setter
    def port(self, value):
        self._port = value

    def LOG_INFO(self, message):
        ms = "[NO.%d %s %s: %s -> %s] IP: %s, MAC: %s, PORT: %s"
        status = self.state
        s_prot_type = "None" if self.sender_prot_type is None else hex(self.sender_prot_type)
        t_prot_type = "None" if self.target_prot_type is None else hex(self.target_prot_type)
        ip_addr = "None" if self.ip_addr is None else util.ip_i2s(self.ip_addr)
        mac_addr = "None" if self.mac_addr is None else util.mac_i2s(self.mac_addr)
        port = "None" if self.port is None else str(self.port)
        logging.info(ms, self.seq(), status, message, s_prot_type, t_prot_type, ip_addr, mac_addr, port)
