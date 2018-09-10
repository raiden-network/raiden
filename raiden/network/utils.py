from itertools import count
from time import sleep
from typing import Optional

import psutil
import requests
from requests import RequestException


def get_free_port(address: str, initial_port: int):
    """Find an unused TCP port in a specified range. This should not
      be used in misson-critical applications - a race condition may
      occur if someone grabs the port before caller of this function
      has chance to use it.
      Parameters:
          address : an ip address of interface to use
          initial_port : port to start iteration with
      Return:
          Iterator that will return next unused port on a specified
          interface
    """

    try:
        # On OSX this function requires root privileges
        psutil.net_connections()
    except psutil.AccessDenied:
        return count(initial_port)

    def _unused_ports():
        for port in count(initial_port):
            # check if the port is being used
            connect_using_port = (
                conn
                for conn in psutil.net_connections()
                if hasattr(conn, 'laddr') and
                conn.laddr[0] == address and
                conn.laddr[1] == port
            )

            # only generate unused ports
            if not any(connect_using_port):
                yield port

    return _unused_ports()


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
