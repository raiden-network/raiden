# -*- coding: utf-8 -*-
import pytest
from ethereum import tester
from ethereum.tester import TransactionFailed

from raiden.blockchain.abi import CONTRACT_MANAGER, CONTRACT_NETTING_CHANNEL
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
)
from raiden.tests.utils.tester import (
    INVALID_KEY,
)
from raiden.utils import privatekey_to_address


def test_nettingchannel_minimum_settle_timeout(private_keys, tester_channelmanager, tester_state):
    """ The netting channel constructor must enforce a minimum settle timeout.

    Also asserts that the constants.py and the netting channel contract values
    are synched.
    """
    pkey0 = private_keys[0]
    pkey1 = private_keys[1]

    log_listener = None

    with pytest.raises(TransactionFailed):
        small_settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MIN - 1
        tester_channelmanager.newChannel(
            privatekey_to_address(pkey1),
            small_settle_timeout,
            sender=pkey0,
        )

    minimum_settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MIN
    netting_channel_address0_hex = tester_channelmanager.newChannel(
        privatekey_to_address(pkey1),
        minimum_settle_timeout,
        sender=pkey0,
    )

    netting_channel = tester.ABIContract(
        tester_state,
        CONTRACT_MANAGER.get_translator(CONTRACT_NETTING_CHANNEL),
        netting_channel_address0_hex,
        log_listener=log_listener,
        default_key=INVALID_KEY,
    )
    # pylint: disable=no-member
    assert netting_channel.settleTimeout(sender=pkey0) == minimum_settle_timeout
