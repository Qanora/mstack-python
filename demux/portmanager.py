import collections


class PortManager:
    def __init__(self):
        self.ports = set()

    def allocate_port(self, port=None):
        if port is None:
            if len(self.ports) >= 49152 - 1024:
                return None
            for port in range(1024, 49152):
                if self.is_available(port):
                    self.ports.add(port)
                    return port
            return None
        else:
            if port not in self.ports:
                return port
            return None

    def release_port(self, port):
        self.ports.remove(port)

    def is_available(self, port):
        return port not in self.ports
