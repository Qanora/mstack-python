import ipaddress

def mac_i2s(mac_addr):
    return "0x%012x" % mac_addr

def ip_i2s(ip_addr):
    return str(ipaddress.ip_address(ip_addr))




