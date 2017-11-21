# -*- coding: utf-8 -*-
import pytest

from raiden.api.python import RaidenAPI


@pytest.mark.parametrize('privatekey_seed', ['test_close_regression:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [1])
def test_close_regression(raiden_network, token_addresses):
    """ The python api was using the wrong balance proof to close the channel,
    thus the close was failling if a transfer was made.
    """
    node1, node2 = raiden_network
    token_address = token_addresses[0]

    api1 = RaidenAPI(node1.raiden)
    api2 = RaidenAPI(node2.raiden)

    amount = 10
    assert api1.transfer(token_address, amount, api2.address)

    api1.close(token_address, api2.address)
