# -*- coding: utf-8 -*-
from __future__ import print_function
from collections import namedtuple

import gevent
import pytest
from ethereum import slogging
from raiden.utils import sha3

# pylint: disable=too-many-locals,too-many-statements,line-too-long
slogging.configure(':DEBUG')


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_direct_transfer_callback(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # @ezdac: These vars are not used anywhere. Please address them
    # messages = setup_messages_cb()
    # mlogger = MessageLogger()
    # a0_address = pex(app0.raiden.address)
    # a1_address = pex(app1.raiden.address)

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]
    asset_manager1 = app1.raiden.managers_by_asset_address.values()[0]

    # @ezdac: These vars are not used anywhere. Please address them
    # channel0 = asset_manager0.partneraddress_channel[app1.raiden.address]
    # channel1 = asset_manager1.partneraddress_channel[app0.raiden.address]
    # balance0 = channel0.balance
    # balance1 = channel1.balance

    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert app1.raiden.address in asset_manager0.partneraddress_channel

    amount = 10

    CALLED = [False]

    def assert_callback(cb_asset, cb_recipient, cb_sender, cb_amount, cb_hashlock):
        # check that callback only gets called once:
        assert not CALLED[0]

        # set nonlocal
        CALLED[0] = True
        assert cb_asset == asset_manager0.asset_address
        assert cb_recipient == app1.raiden.address
        assert cb_sender == app0.raiden.address
        assert cb_amount == amount
        assert cb_hashlock is None

    # register callbacks to DirectTransfers (channel.py) and LockedTransfers (transfermanager.py)
    app1.raiden.api.register_on_withdrawable_callbacks(assert_callback)

    # transfer with a direct path
    app0.raiden.api.transfer(
        asset_manager0.asset_address,
        amount,
        target=app1.raiden.address,
    )
    gevent.sleep(1)

    # and check execution
    assert CALLED[0]


@pytest.mark.parametrize('blockchain_type', ['mock'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_on_hashlock_result_callback(raiden_network):
    app0, app1 = raiden_network  # pylint: disable=unbalanced-tuple-unpacking

    # @ezdac: These vars are not used anywhere. Please address them
    # messages = setup_messages_cb()
    # mlogger = MessageLogger()
    # a0_address = pex(app0.raiden.address)
    # a1_address = pex(app1.raiden.address)

    asset_manager0 = app0.raiden.managers_by_asset_address.values()[0]
    asset_manager1 = app1.raiden.managers_by_asset_address.values()[0]

    # @ezdac: These vars are not used anywhere. Please address them
    # channel0 = asset_manager0.partneraddress_channel[app1.raiden.address]
    # channel1 = asset_manager1.partneraddress_channel[app0.raiden.address]
    # balance0 = channel0.balance
    # balance1 = channel1.balance

    assert asset_manager0.asset_address == asset_manager1.asset_address
    assert app1.raiden.address in asset_manager0.partneraddress_channel

    amount = 10

    hashlock = sha3('hashlock')

    CALLED = [False]

    def assert_callback(cb_asset, cb_recipient, cb_sender, cb_amount, cb_hashlock):
        # check that callback only gets called once:
        assert not CALLED[0]

        # set nonlocal
        CALLED[0] = True
        assert cb_asset == asset_manager0.asset_address
        assert cb_recipient == app1.raiden.address
        assert cb_sender == app0.raiden.address
        assert cb_amount == amount
        assert cb_hashlock == hashlock

    # mock the transfer container: XXX eventually use messages.MediatedTransfer() message instead
    Transfer = namedtuple('Transfer', ['asset', 'recipient', 'initiator', 'transferred_amount'])
    transfer = Transfer(asset_manager0.asset_address,
                        app1.raiden.address,
                        app0.raiden.address,
                        amount)

    tm1 = asset_manager1.transfermanager

    # inject the transfer in the dicts:
    tm1.transfertasks[hashlock] = 'task'
    tm1.endtask_transfer_mapping['task'] = transfer

    # register the callback
    tm1.register_callback_for_result(assert_callback)

    # and trigger a hashlock result, calling the callback
    tm1.on_hashlock_result(hashlock=hashlock, success=True)

    # check for execution
    assert CALLED[0]

    # check for cleared transfertask
    assert 'task' not in tm1.endtask_transfer_mapping
    # check that callback is still registered
    assert assert_callback in tm1.on_result_callbacks
