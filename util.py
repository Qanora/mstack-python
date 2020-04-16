import ipaddress
def bytes_to_string(data):
    a = int.from_bytes(data, 'big')
    return "0x%012x" % a

def ip_to_string(data):
    return str(ipaddress.ip_address(bytes(data)))




