import pytest

from raiden.utils import split_endpoint
from raiden.utils.typing import Endpoint


def test_split_endpoint_valid():
    host, port = split_endpoint(Endpoint("https://rpc.slock.it/goerli"))
    assert host == "rpc.slock.it"
    assert port == 0

    host, port = split_endpoint(Endpoint("https://rpc.slock.it:443/goerli"))
    assert host == "rpc.slock.it"
    assert port == 443


def test_split_endpoint_invalid():
    with pytest.raises(ValueError):
        split_endpoint(Endpoint("/invalid/endpoint"))
