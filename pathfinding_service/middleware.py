from typing import Tuple

import gevent
from requests.exceptions import ConnectionError, HTTPError, Timeout, TooManyRedirects
from web3.middleware.exception_retry_request import check_if_retry_on_failure


def http_retry_with_backoff_middleware(
    make_request,
    web3,
    errors: Tuple = (ConnectionError, HTTPError, Timeout, TooManyRedirects),
    retries: int = 10,
    first_backoff: float = 0.2,
    backoff_factor: float = 2,
):
    """ Retry requests with exponential backoff

    Creates middleware that retries failed HTTP requests and exponentially
    increases the backoff between retries. Meant to replace the default
    middleware `http_retry_request_middleware` for HTTPProvider.
    """
    def middleware(method, params):
        backoff = first_backoff
        if check_if_retry_on_failure(method):
            for i in range(retries):
                try:
                    return make_request(method, params)
                except errors:
                    if i < retries - 1:
                        gevent.sleep(backoff)
                        backoff *= backoff_factor
                        continue
                    else:
                        raise
        else:
            return make_request(method, params)
    return middleware
