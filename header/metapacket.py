#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import util
class MetaPacket:
    def __init__(self, _sender_prot_type, _target_prot_type, _payload):
        self._sender_prot_type = _sender_prot_type
        self._target_prot_type = _target_prot_type
        self._payload = _payload
        self._mac_addr = None
        self._ip_addr = None

    def sender_prot_type(self) -> str:
        return self._sender_prot_type

    def payload(self):
        return self._payload

    def target_prot_type(self) -> str:
        return self._target_prot_type

    def set_ip_addr(self, ip_addr):
        self._ip_addr = ip_addr

    def set_mac_addr(self, mac_addr):
        self._mac_addr = mac_addr

    def ip_addr(self):
        return self._ip_addr

    def mac_addr(self):
        return self._mac_addr

    def LOG_INFO(self, status):
        logging.info("[METAPACKET][" + status + "]:" + " [FROM]:" + self.sender_prot_type() +
                     " [TO]:" + self.target_prot_type() + " [DATA] IP:" + util.ip_to_string(self.ip_addr())
                     + " MAC:" +util.bytes_to_string(self.mac_addr()))