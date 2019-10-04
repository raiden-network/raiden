import gevent

from raiden.network.rpc.client import geth_discover_next_available_nonce
from raiden.tests.utils.factories import make_address


def test_geth_discover_next_available_nonce(
    deploy_client, skip_if_parity  # pylint: disable=unused-argument
):
    """ Test that geth_discover_next_available nonce works correctly

    Reproduced the problem seen here:
    https://github.com/raiden-network/raiden/pull/3683#issue-264551799
    """

    greenlets = {
        gevent.spawn(deploy_client.send_transaction, make_address(), 50000)  # to  # startgas
        for _ in range(100)
    }
    gevent.joinall(set(greenlets), raise_error=True)

    nonce = geth_discover_next_available_nonce(
        web3=deploy_client.web3, address=deploy_client.address
    )
    assert nonce > 0
    assert nonce <= 100
