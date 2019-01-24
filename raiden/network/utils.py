import errno
import socket
from itertools import count, repeat
from socket import SocketKind
from time import sleep
from typing import Optional

import requests
from requests import RequestException


def get_free_port(
        bind_address: str = '127.0.0.1',
        initial_port: int = 0,
        socket_kind: SocketKind = SocketKind.SOCK_STREAM,
):
    """
    Find an unused TCP port.
    This should not be used in misson-critical applications - a race condition may occur if
    someone grabs the port before caller of this function has chance to use it.

    If `initial_port` is passed the function will try to find a port as close as possible.
    Otherwise a random port is chosen by the OS.

    Returns an iterator that will return an unused port on the specified interface.
    """

    def _port_generator():
        if initial_port == 0:
            next_port = repeat(0)
        else:
            next_port = count(start=initial_port)
        for i in next_port:
            sock = socket.socket(socket.AF_INET, socket_kind)
            try:
                sock.bind((bind_address, i))
            except OSError as ex:
                if ex.errno == errno.EADDRINUSE:
                    continue
            port = sock.getsockname()[1]
            sock.close()
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
