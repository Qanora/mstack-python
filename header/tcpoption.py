from header import Structure, TypeLen


class EOL(Structure):
    _fields_ = [
        (TypeLen.L1, "type")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 0
        self.name = "EOL"


class NOP(Structure):
    _fields_ = [
        (TypeLen.L1, "type")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 1
        self.name = "NOP"


class MSS(Structure):
    _fields_ = [
        (TypeLen.L1, "type"),
        (TypeLen.L1, "length"),
        (TypeLen.L2, "value")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 2
        self.length = 4
        self.value = 1460
        self.name = "MSS"

    def merge(self, remote_mss_option):
        return remote_mss_option


class WSOPT(Structure):
    _fields_ = [
        (TypeLen.L1, "type"),
        (TypeLen.L1, "length"),
        (TypeLen.L1, "value")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 3
        self.length = 3
        self.name = "WSOPT"


class SACK_PERMITTED(Structure):
    _fields_ = [
        (TypeLen.L1, "type"),
        (TypeLen.L1, "length")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 4
        self.length = 2
        self.name = "SACK_PERMITTED"

    def merge(self, remote_sack_permitted):
        return remote_sack_permitted

class TSOPT(Structure):
    _fields_ = [
        (TypeLen.L1, "type"),
        (TypeLen.L1, "length"),
        (TypeLen.L8, "value")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 8
        self.length = 10
        self.name = "TSOPT"


class TCP_MD5(Structure):
    _fields_ = [
        (TypeLen.L1, "type"),
        (TypeLen.L1, "length"),
        (TypeLen.L16, "value")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 19
        self.length = 18
        self.name = "TCP_MD5"


class UTO(Structure):
    _fields_ = [
        (TypeLen.L1, "type"),
        (TypeLen.L1, "length"),
        (TypeLen.L2, "value")
    ]

    def __init__(self, bytedata=None):
        super().__init__(bytedata)
        self.type = 28
        self.length = 4
        self.name = "UTO"


class TcpOptionManager:
    options_map = {
        0: (1, EOL),
        1: (1, NOP),
        2: (4, MSS),
        3: (3, WSOPT),
        4: (2, SACK_PERMITTED),
        8: (10, TSOPT),
        19: (18, TCP_MD5),
        28: (4, UTO)
    }

    options_config = {
        2: MSS(),
        4: SACK_PERMITTED(),
    }

    @classmethod
    def init_options(cls):
        options = bytearray(0)
        for k, v in TcpOptionManager.options_config:
            options += v.buffer
        if len(options) % 2 == 1:
            options += NOP().buffer
        return options

    @classmethod
    def merge_options(cls, options):
        options_config = {}
        while options:
            kind = options[0]
            if kind in TcpOptionManager.options_map:
                length, clss = TcpOptionManager.options_map[kind]
                data = options[:length]
                # if len(data) == 1:
                #    data = bytearray(int.to_bytes(data, 1, 'big'))
                # print(data.hex())
                options_config[kind] = clss(data)
                options = options[length:]
            else:
                break

        ret_options = {}
        for k, v in TcpOptionManager.options_config.items():
            if k in options_config:
                ret_options[k] = v.merge(options_config[k])

        return ret_options

    @classmethod
    def encode_options(cls, options):
        bin_options = bytearray(0)
        for k, v in options.items():
            bin_options += v.buffer
        while len(bin_options) % 4 != 0:
            bin_options += NOP().buffer
        return bin_options
