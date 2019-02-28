import requests
from raiden.constants import DEFAULT_HTTP_REQUEST_TIMEOUT
from raiden.utils import typing


def get_pfs_info(url: str) -> typing.Optional[typing.Dict]:
    try:
        return requests.get(f'{url}/api/v1/info', timeout=DEFAULT_HTTP_REQUEST_TIMEOUT).json()
    except requests.exceptions.RequestException:
        return None
