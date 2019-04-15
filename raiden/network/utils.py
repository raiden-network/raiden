import errno
import socket
from contextlib import closing
from itertools import count, repeat
from socket import SocketKind
from time import sleep
from typing import Optional

import requests
from requests import RequestException


def get_free_port(
        initial_port: int = 0,
        socket_kind: SocketKind = SocketKind.SOCK_STREAM,
        reliable: bool = True,
):
    """
    Find an unused TCP port.

    Unless the `reliable` parameter is set to `True` (the default) this is prone to race
    conditions - some other process may grab the port before the caller of this function has
    a chance to use it.
    When using `reliable` the port is forced into TIME_WAIT mode, ensuring that it will not be
    considered 'free' by the OS for the next 60 seconds. This does however require that the
    process using the port sets SO_REUSEADDR on it's sockets. Most 'server' applications do.

    If `initial_port` is passed the function will try to find a port as close as possible.
    Otherwise a random port is chosen by the OS.

    Returns an iterator that will return unused port numbers.
    """

    def _port_generator():
        if initial_port == 0:
            next_port = repeat(0)
        else:
            next_port = count(start=initial_port)

        for port_candidate in next_port:
            # Don't inline the variable until https://github.com/PyCQA/pylint/issues/1437 is fixed
            sock = socket.socket(socket.AF_INET, socket_kind)
            with closing(sock):
                if reliable:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind(('127.0.0.1', port_candidate))
                except OSError as ex:
                    if ex.errno == errno.EADDRINUSE:
                        continue

                sock_addr = sock.getsockname()
                port = sock_addr[1]

                if reliable:
                    # Connect to the socket to force it into TIME_WAIT state
                    sock.listen(1)
                    # see above
                    sock2 = socket.socket(socket.AF_INET, socket_kind)
                    with closing(sock2):
                        sock2.connect(sock_addr)
                        sock.accept()
            yield port
    return _port_generator()


def get_http_rtt(
        url: str,
        samples: int = 3,
        method: str = 'head',
        timeout: int = 1,
) -> Optional[float]:
    """
    Determine the average HTTP RTT to `url` over the number of `samples`.
    Returns `None` if the server is unreachable.
    """
    durations = []
    for _ in range(samples):
        try:
            durations.append(
                requests.request(method, url, timeout=timeout).elapsed.total_seconds(),
            )
        except (RequestException, OSError):
            return None
        except Exception as ex:
            print(ex)
            return None
        # Slight delay to avoid overloading
        sleep(.125)
    return sum(durations) / samples
