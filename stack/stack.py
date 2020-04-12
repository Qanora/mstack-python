class Stack:
    def __init__(self):
        self.transport_protocol = []
        self.network_protocol = []

    def register_transport(self, transport):
        self.transport_protocol.append(transport)

    def register_network(self, network):
        self.network_protocol.append(network)


stack = Stack()