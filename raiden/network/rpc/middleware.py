import functools
from json.decoder import JSONDecodeError

import lru
from web3.middleware.cache import construct_simple_cache_middleware

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


def _should_cache(_method, _params, response):
    if 'error' in response:
        return False
    elif 'result' not in response:
        return False

    if response['result'] is None:
        return False
    return True


block_hash_cache_middleware = construct_simple_cache_middleware(
    # default sample size of gas price strategies is 120
    cache_class=functools.partial(lru.LRU, 150),
    rpc_whitelist=BLOCK_HASH_CACHE_RPC_WHITELIST,
)
