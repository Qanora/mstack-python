import ipaddress


def checksum(bytedata: bytearray):
    bt = 0
    for i in range(0, len(bytedata), 2):
        bt += int.from_bytes(bytedata[i:i + 2], 'big')
    bt = (bt >> 16) + (bt & 0xffff)
    bt += (bt >> 16)
    bt = (~bt) & 0xffff
    return bt

def mac_i2s(mac_addr):
    return "0x%012x" % mac_addr


def mac_b2i(mac_addr):
    return int.from_bytes(mac_addr, 'big')


def ip_i2s(ip_addr):
    return str(ipaddress.ip_address(ip_addr))


def ip_s2i(ip_addr) -> int:
    return int.from_bytes(ipaddress.ip_address(ip_addr).packed, 'big')