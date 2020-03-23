import pytest
from eth_typing import URI
from requests.exceptions import ConnectionError as RequestsConnectionError
from web3 import HTTPProvider, Web3

from raiden.network.rpc.client import JSONRPCClient
from raiden.tests.utils.factories import make_privatekey_bin


def test_connection_issues() -> None:
    # 641 is a port registered with IANA for this service:
    #
    # repcmd            641/tcp
    # repcmd            641/udp
    #
    # This is a comcast utility agent that is unlikely to be running. The numbe
    # was chosen with. `sum(ord(c) for c in 'random')`

    web3 = Web3(HTTPProvider(URI("http://localhost:641")))

    with pytest.raises(RequestsConnectionError):
        JSONRPCClient(web3=web3, privkey=make_privatekey_bin())
