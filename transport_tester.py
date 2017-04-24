from gevent import monkey
monkey.patch_all()  # noqa
import sys
import time

from ethereum import slogging

from raiden.network.transport import UDPTransport
from raiden.network.sockfactory import socket_factory


class DummyProtocol(object):

    def __init__(self):
        self.raiden = None

    def receive(self, data):
        print data


if __name__ == "__main__":
    slogging.configure(':DEBUG')
    with socket_factory('0.0.0.0', 8885) as mapped_socket:
        print mapped_socket
        t = UDPTransport(mapped_socket.socket, protocol=DummyProtocol())
        while True:
            time.sleep(1)
            if len(sys.argv) > 1:
                t.send(None, (sys.argv[1], 8885), b'hello')
