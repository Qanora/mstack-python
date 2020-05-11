import abc
import struct

class Protocol(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def recv(cls, packet):
        pass


class StructField:
    def __init__(self, format, offset):
        self.format = format
        self.offset = offset

    def __get__(self, ins, cls):
        if ins is None:
            return self
        else:
            r = struct.unpack_from(self.format, ins.header, self.offset)
            if len(r) == 1:
                return r[0]
            offset = 0
            ret = 0
            r = list(r)
            for k, v in zip(self.format[1:][::-1], r[::-1]):
                v = v << offset * 8
                ret = ret | v
                offset += struct.calcsize(k)
            return ret

    def __set__(self, ins, val):
        if len(self.format[1:]) == 1:
            struct.pack_into(self.format, ins.header, self.offset, val)
        else:
            vals = []
            cur = val
            for v in self.format[1:][::-1]:
                offset = struct.calcsize(v) * 8
                vals.append(cur & ((1 << offset) - 1))
                cur = cur >> offset
            vals = vals[::-1]
            struct.pack_into(self.format, ins.header, self.offset, *vals)


class StructureMeta(type):
    def __init__(cls, name, bases, namespace, **kwarg):
        fields = getattr(cls, '_fields_', [])
        byts_order = '!'
        offset = 0
        for fmt, fieldname in fields:
            fmt = byts_order + fmt
            setattr(cls, fieldname, StructField(fmt, offset))
            offset += struct.calcsize(fmt)
        setattr(cls, 'header_size', offset)
        super().__init__(name, bases, namespace)


class Structure(metaclass=StructureMeta):
    def __init__(self, bytedata=None):
        if bytedata is None:
            bytedata = bytearray(self.header_size)
        self._buffer = bytearray(bytedata)
        setattr(self, 'payload_size', len(self._buffer) - getattr(self, 'header_size'))
        setattr(self, 'payload', self._buffer[getattr(self, 'header_size'):])
        setattr(self, 'header', self._buffer[:getattr(self, 'header_size')])

    @property
    def buffer(self):
        return self.header + self.payload



class TypeLen:
    L6 = "HI"
    L4 = "I"
    L2 = "H"
    L1 = "B"

