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

    def send_transaction(to, startgas):
        deploy_client.get_next_transaction().send_transaction(to=to, startgas=startgas)

    greenlets = {
        gevent.spawn(send_transaction, make_address(), 50000) for _ in range(100)  # to  # startgas
    }
    gevent.joinall(set(greenlets), raise_error=True)

    nonce = geth_discover_next_available_nonce(
        web3=deploy_client.web3, address=deploy_client.address
    )
    assert nonce > 0
    assert nonce <= 100
