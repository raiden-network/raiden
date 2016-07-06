# -*- coding: utf8 -*-
import gevent
import gevent.monkey
import pytest

from ethereum import slogging

# Monkey patch subprocess.Popen used by solidity wrapper
gevent.monkey.patch_socket()  # patch_subprocess()
slogging.configure(':ERROR,eth.chain.tx:DEBUG,jsonrpc:DEBUG,eth.vm:TRACE')


@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('timeout', [3])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_event_new_channel(deployed_network, deposit, settle_timeout):
    app0, app1 = deployed_network  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.chain.asset_addresses[0]

    assert len(app0.raiden.assetmanagers[asset_address].channels) == 0
    assert len(app1.raiden.assetmanagers[asset_address].channels) == 0

    netcontract_address = app0.raiden.chain.new_netting_contract(
        asset_address,
        app0.raiden.address,
        app1.raiden.address,
        settle_timeout,
    )

    app0.raiden.chain.asset_approve(
        asset_address,
        netcontract_address,
        deposit,
    )

    app0.raiden.chain.deposit(
        asset_address,
        netcontract_address,
        app0.raiden.address,
        deposit,
    )

    app1.raiden.chain.asset_approve(
        asset_address,
        netcontract_address,
        deposit,
    )

    app1.raiden.chain.deposit(
        asset_address,
        netcontract_address,
        app1.raiden.address,
        deposit,
    )

    gevent.sleep(0.1)  # let the task run

    assert len(app0.raiden.assetmanagers[asset_address].channels) == 1
    assert len(app1.raiden.assetmanagers[asset_address].channels) == 1
