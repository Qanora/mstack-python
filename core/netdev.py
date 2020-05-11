from core.tuntap import Tuntap


class NetDevManager:
    log_format = "[NETDEV: %s] rx:%s tx:%s"
    _running = True
    _net_dev_ip_map = {}

    @classmethod
    def register_net_dev(cls, net_dev):
        NetDevManager._net_dev_ip_map[net_dev.ip_addr] = net_dev
        net_dev.active()

    @classmethod
    def get_net_dev_by_ip(cls, ip_addr):
        return NetDevManager._net_dev_ip_map[ip_addr]

