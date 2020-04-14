from stack.stack import Stack
import logging
from header.arp import Arp


class Nic:
    def __init__(self, stack: Stack, link): #Link):
        self.stack = stack
        self.link = link
        self.link.attach(self.stack)

