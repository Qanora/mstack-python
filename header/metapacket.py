#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import util


class MetaPacket:
    def __init__(self, _sender_prot_type: int, _target_prot_type: int, _payload):
        self._sender_prot_type = _sender_prot_type
        self._target_prot_type = _target_prot_type
        self._payload = _payload
        self._mac_addr = None
        self._ip_addr = None

    def sender_prot_type(self) -> int:
        return self._sender_prot_type

    def payload(self):
        return self._payload

    def target_prot_type(self) -> int:
        return self._target_prot_type

    def set_ip_addr(self, ip_addr: int):
        self._ip_addr = ip_addr

    def set_mac_addr(self, mac_addr: int):
        self._mac_addr = mac_addr

    def ip_addr(self) -> int:
        return self._ip_addr

    def mac_addr(self) -> int:
        return self._mac_addr

    def LOG_INFO(self, status):
        ms = "[%s]: [%s -> %s] [IP: %s, MAC: %s]"
        s_prot_type = "None" if self.sender_prot_type() is None else hex(self.sender_prot_type())
        t_prot_type = "None" if self.target_prot_type() is None else hex(self.target_prot_type())
        ip_addr = "None" if self.ip_addr() is None else util.ip_i2s(self.ip_addr())
        mac_addr = "None" if self.mac_addr() is None else util.mac_i2s(self.mac_addr())
        logging.info(ms, status, s_prot_type, t_prot_type, ip_addr, mac_addr)
