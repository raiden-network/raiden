from typing import Dict, Union

import requests
from raiden.constants import DEFAULT_HTTP_REQUEST_TIMEOUT


def get_pfs_info(url: str) -> Union[Dict, bool]:
    try:
        return requests.get('{}/api/v1/info'.format(url),
                            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT).json()
    except requests.exceptions.RequestException:
        return False
