# -*- coding: utf-8 -*-
import pytest
from ethereum.tools import tester
from ethereum.tools.tester import TransactionFailed

from raiden.blockchain.abi import CONTRACT_MANAGER, CONTRACT_NETTING_CHANNEL
from raiden.constants import (
    NETTINGCHANNEL_SETTLE_TIMEOUT_MIN,
    NETTINGCHANNEL_SETTLE_TIMEOUT_MAX,
)
from raiden.utils import privatekey_to_address


def test_nettingchannel_settle_timeout_inrange(private_keys, tester_channelmanager, tester_chain):
    """ The netting channel constructor must enforce that settle timeout is in
    the valid range.

    Also asserts that the constants.py and the netting channel contract values
    are synched.
    """
    pkey0 = private_keys[0]
    pkey1 = private_keys[1]
    pkey2 = private_keys[2]

    with pytest.raises(TransactionFailed):
        small_settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MIN - 1
        tester_channelmanager.newChannel(
            privatekey_to_address(pkey1),
            small_settle_timeout,
            sender=pkey0,
        )

    with pytest.raises(TransactionFailed):
        big_settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MAX + 1
        tester_channelmanager.newChannel(
            privatekey_to_address(pkey1),
            big_settle_timeout,
            sender=pkey0,
        )

    minimum_settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MIN
    netting_channel_address0_hex = tester_channelmanager.newChannel(
        privatekey_to_address(pkey1),
        minimum_settle_timeout,
        sender=pkey0,
    )
    max_settle_timeout = NETTINGCHANNEL_SETTLE_TIMEOUT_MAX
    netting_channel_address1_hex = tester_channelmanager.newChannel(
        privatekey_to_address(pkey2),
        max_settle_timeout,
        sender=pkey0,
    )

    netting_channel = tester.ABIContract(
        tester_chain,
        CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL),
        netting_channel_address0_hex
    )
    # pylint: disable=no-member
    assert netting_channel.settleTimeout(sender=pkey0) == minimum_settle_timeout
    netting_channel2 = tester.ABIContract(
        tester_chain,
        CONTRACT_MANAGER.get_abi(CONTRACT_NETTING_CHANNEL),
        netting_channel_address1_hex
    )
    assert netting_channel2.settleTimeout(sender=pkey0) == max_settle_timeout
