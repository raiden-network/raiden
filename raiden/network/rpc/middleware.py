import functools
from json.decoder import JSONDecodeError
from typing import Tuple

import gevent
from cachetools import LRUCache
from requests import exceptions
from web3.middleware.cache import construct_simple_cache_middleware
from web3.middleware.exception_retry_request import check_if_retry_on_failure

from raiden.exceptions import EthNodeCommunicationError


def make_connection_test_middleware():
    def connection_test_middleware(make_request, web3):
        """ Creates middleware that checks if the provider is connected. """

        def middleware(method, params):
            try:
                if web3.isConnected():
                    return make_request(method, params)
                else:
                    raise EthNodeCommunicationError('Web3 provider not connected')

            # the isConnected check doesn't currently catch JSON errors
            # see https://github.com/ethereum/web3.py/issues/866
            except JSONDecodeError:
                raise EthNodeCommunicationError('Web3 provider not connected')

        return middleware
    return connection_test_middleware


connection_test_middleware = make_connection_test_middleware()


BLOCK_HASH_CACHE_RPC_WHITELIST = {
    'eth_getBlockByHash',
}


block_hash_cache_middleware = construct_simple_cache_middleware(
    # default sample size of gas price strategies is 120
    cache_class=functools.partial(LRUCache, 150),
    rpc_whitelist=BLOCK_HASH_CACHE_RPC_WHITELIST,
)


# This one is taken directly from the PFS code:
# https://github.com/raiden-network/raiden-services/blob/51b2b3093915c482e3d8307a09f2952ffa3c6c7e/src/pathfinding_service/middleware.py
# We could potentially move it to a common code repository
def http_retry_with_backoff_middleware(
        make_request,
        web3,  # pylint: disable=unused-argument
        errors: Tuple = (
            exceptions.ConnectionError,
            exceptions.HTTPError,
            exceptions.Timeout,
            exceptions.TooManyRedirects,
        ),
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
