import errno
import socket
import sys
from contextlib import closing
from itertools import count, repeat
from socket import SocketKind
from time import sleep

import psutil
import requests
from requests import RequestException

from raiden.utils.typing import Iterable, Optional, Port

LOOPBACK = "127.0.0.1"

# The solution based on psutils does not work on MacOS because it needs
# root access
if sys.platform == "darwin":

    def _unused_ports(initial_port: Optional[int]) -> Iterable[Port]:
        socket_kind: SocketKind = SocketKind.SOCK_STREAM

        if not initial_port:
            next_port = repeat(0)
        else:
            next_port = count(start=initial_port)

        for port_candidate in next_port:
            # Don't inline the variable until
            # https://github.com/PyCQA/pylint/issues/1437 is fixed
            sock = socket.socket(socket.AF_INET, socket_kind)
            with closing(sock):
                # Force the port into TIME_WAIT mode, ensuring that it will not
                # be considered 'free' by the OS for the next 60 seconds. This
                # does however require that the process using the port sets
                # SO_REUSEADDR on it's sockets. Most 'server' applications do.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((LOOPBACK, port_candidate))
                except OSError as ex:
                    if ex.errno == errno.EADDRINUSE:
                        continue
                    raise

                sock_addr = sock.getsockname()
                port = sock_addr[1]

                # Connect to the socket to force it into TIME_WAIT state (see
                # above)
                sock.listen(1)
                sock2 = socket.socket(socket.AF_INET, socket_kind)
                with closing(sock2):
                    sock2.connect(sock_addr)
                    sock.accept()

            yield Port(port)


else:

    def _unused_ports(initial_port: Optional[int]) -> Iterable[Port]:
        initial_port = initial_port or 27854

        for port in count(initial_port):
            connect_using_port = (
                conn
                for conn in psutil.net_connections()
                if hasattr(conn, "laddr") and conn.laddr[0] == LOOPBACK and conn.laddr[1] == port
            )

            if not any(connect_using_port):
                yield Port(port)


def get_free_port(initial_port: Optional[int] = None) -> Iterable[Port]:
    """Find an unused TCP port.

    If `initial_port` is passed the function will try to find a port as close as possible.
    Otherwise a random port is chosen by the OS.

    Returns an iterator that will return unused port numbers.
    """
    return _unused_ports(initial_port=initial_port)


def get_http_rtt(
    url: str, samples: int = 3, method: str = "head", timeout: int = 1
) -> Optional[float]:
    """
    Determine the average HTTP RTT to `url` over the number of `samples`.
    Returns `None` if the server is unreachable.
    """
    durations = []
    for _ in range(samples):
        try:
            durations.append(
                requests.request(method, url, timeout=timeout).elapsed.total_seconds()
            )
        except (RequestException, OSError):
            return None
        except Exception as ex:
            print(ex)
            return None
        # Slight delay to avoid overloading
        sleep(0.125)
    return sum(durations) / samples
