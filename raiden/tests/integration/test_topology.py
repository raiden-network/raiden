# -*- coding: utf-8 -*-
import pytest
import gevent

from raiden.tests.utils.network import setup_channels

#  This test will create a topology with two possible routes from 0 to 4
#
#
#  0 ----------> 1 -------> 2 -----> 4
#                |                   ^
#                +--------> 3 -------+
#
#
#  The transfer should proceed without triggering an assert. ATM an assert exc.
#   is raised because RoutesState object takes a first hop from both routes
#   as an input and then check for duplicate values in that list.
#


@pytest.mark.parametrize('number_of_nodes', [5])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('blockchain_type', ['tester'])
def test_topology(raiden_network, token_amount, token_addresses, settle_timeout, deposit):
    # pylint: disable=line-too-long,too-many-statements,too-many-locals

    app0, app1, app2, app3, app4 = raiden_network
    token = token_addresses[0]
    app_channels = [(app0, app1), (app1, app3), (app3, app4),
                                  (app1, app2), (app2, app4)]
    setup_channels(
        token,
        app_channels,
        deposit,
        settle_timeout,
    )
    gevent.sleep(1)
    transfer = app0.raiden.transfer_async(
        token,
        1,
        app4.raiden.address
    )
    assert transfer
    transfer.wait()
