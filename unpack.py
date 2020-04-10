import struct


def unpack6(encode):
    a, b = struct.unpack('!IH', encode)
    return a << 8 | b


def unpack2(encode):
    return struct.unpack('!h', encode)[0]
