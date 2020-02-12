from typing import Callable, Dict, Tuple


class Eth:
    blockNumber: int


class Web3:
    toBytes = Callable
    eth = Eth

    def __init__(self, providers: Tuple = ..., middlewares: Dict = ..., modules: Dict = ...) -> None:
        ...


class HTTPProvider:
    ...
