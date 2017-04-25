"""  # noqa
Usage:
    transport_tester.py [--stun-host=<stun host>] [--ip=<ip>] [--port=<port>] [<target_ip_optional_port>]

Options:
    -p --port=<port>                    Port number to use [default: 8885].
    -i --ip=<ip>                        IP to use [default: 0.0.0.0].
    -H --stun-host=<stun host>          A specific STUN host to use.
"""
from gevent import monkey
monkey.patch_all()  # noqa
import time

from docopt import docopt
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
    options = docopt(__doc__)
    port = int(options['--port'])
    target = options['<target_ip_optional_port>']
    stun_host = options['--stun-host']
    ip = options['--ip']
    if target and ':' in target:
        target, target_port = target.split(':')
        target_port = int(target_port)
    else:
        target_port = port
    with socket_factory(ip, port, stun_host=stun_host) as mapped_socket:
        print mapped_socket
        t = UDPTransport(mapped_socket.socket, protocol=DummyProtocol())
        while True:
            time.sleep(1)
            if target:
                t.send(None, (target, target_port), b'hello')
