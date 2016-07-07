# -*- coding: utf8 -*-
import gevent
import gevent.monkey
import pytest

from ethereum import slogging

from raiden.tests.utils.transfer import assert_synched_channels

# Monkey patch subprocess.Popen used by solidity wrapper
gevent.monkey.patch_socket()  # patch_subprocess()
slogging.configure(
    ':DEBUG'
    ',eth.chain.tx:DEBUG'
    ',jsonrpc:DEBUG'
    ',eth.vm:TRACE,eth.pb.tx:TRACE,eth.pb.msg:TRACE,eth.pb.msg.state:TRACE'
)


@pytest.mark.xfail(reason='flaky test')  # this test has timeout issues that need to be fixed
@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('timeout', [3])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_event_new_channel(deployed_network, deposit, settle_timeout):
    app0, app1 = deployed_network  # pylint: disable=unbalanced-tuple-unpacking

    asset_address = app0.raiden.chain.asset_addresses[0]

    assert len(app0.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 0
    assert len(app1.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 0

    netcontract_address = app0.raiden.chain.new_netting_contract(
        asset_address,
        app0.raiden.address,
        app1.raiden.address,
        settle_timeout,
    )

    gevent.sleep(0.1)  # let the task run

    # channel is created but not opened and without funds
    assert len(app0.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 1
    assert len(app1.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 1

    channel0 = app0.raiden.managers_by_asset_address[asset_address].channels_by_partner.values()[0]
    channel1 = app1.raiden.managers_by_asset_address[asset_address].channels_by_partner.values()[0]

    assert_synched_channels(
        channel0, 0, [],
        channel1, 0, [],
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

    gevent.sleep(0.1)  # let the task run

    # channel is open but single funded
    assert len(app0.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 1
    assert len(app1.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 1

    channel0 = app0.raiden.managers_by_asset_address[asset_address].channels_by_partner.values()[0]
    channel1 = app1.raiden.managers_by_asset_address[asset_address].channels_by_partner.values()[0]

    assert_synched_channels(
        channel0, deposit, [],
        channel1, 0, [],
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

    # channel is open and funded by both participants
    assert len(app0.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 1
    assert len(app1.raiden.managers_by_asset_address[asset_address].channels_by_partner) == 1

    channel0 = app0.raiden.managers_by_asset_address[asset_address].channels_by_partner.values()[0]
    channel1 = app1.raiden.managers_by_asset_address[asset_address].channels_by_partner.values()[0]

    assert_synched_channels(
        channel0, deposit, [],
        channel1, deposit, [],
    )
