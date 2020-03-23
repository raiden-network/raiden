import functools

from cachetools import LRUCache
from web3.middleware.cache import construct_simple_cache_middleware
from web3.types import RPCEndpoint

BLOCK_HASH_CACHE_RPC_WHITELIST = {RPCEndpoint("eth_getBlockByHash")}


block_hash_cache_middleware = construct_simple_cache_middleware(
    # default sample size of gas price strategies is 120
    cache_class=functools.partial(LRUCache, 150),  # type: ignore
    rpc_whitelist=BLOCK_HASH_CACHE_RPC_WHITELIST,
)
