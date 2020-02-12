import gevent

from raiden.network.rpc.client import (
    EthTransfer,
    JSONRPCClient,
    gas_price_for_fast_transaction,
    geth_discover_next_available_nonce,
)
from raiden.tests.utils.factories import make_address


def test_geth_discover_next_available_nonce(
    deploy_client: JSONRPCClient, skip_if_parity: bool  # pylint: disable=unused-argument
) -> None:
    """ Test that geth_discover_next_available nonce works correctly

    Reproduced the problem seen here:
    https://github.com/raiden-network/raiden/pull/3683#issue-264551799
    """

    def send_transaction(to):
        deploy_client.transact(
            EthTransfer(
                to_address=to,
                value=0,
                gas_price=gas_price_for_fast_transaction(deploy_client.web3),
            )
        )

    greenlets = {gevent.spawn(send_transaction, to=make_address()) for _ in range(100)}
    gevent.joinall(set(greenlets), raise_error=True)

    nonce = geth_discover_next_available_nonce(
        web3=deploy_client.web3, address=deploy_client.address
    )
    assert nonce > 0
    assert nonce <= 100
