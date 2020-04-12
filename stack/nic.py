from stack.stack import Stack
# from link.link import Link


class Nic:
    def __init__(self, stack: Stack, link): #Link):
        self.stack = stack
        self.link = link
        self.link.attach(self)

    def deliver(self, payload: bytearray) -> None:
        pass
