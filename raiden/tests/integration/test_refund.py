# -*- coding: utf-8 -*-
import pytest

from raiden.tests.utils.transfer import (
    direct_transfer,
    channel,
    get_sent_transfer,
)
from raiden.tests.utils.network import CHAIN
from raiden.messages import RefundTransfer


@pytest.mark.parametrize('privatekey_seed', ['test_refund_messages:{}'])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('settle_timeout', [50])
def test_refund_messages(raiden_chain, token_addresses, deposit):
    # The network has the following topology:
    #
    #   App0 <---> App1 <---> App2
    app0, app1, app2 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    token_address = token_addresses[0]
    channel_1_0 = channel(app1, app0, token_address)
    channel_1_2 = channel(app1, app2, token_address)

    # Exhaust the channel App1 <-> App2 (to force the refund transfer)
    amount = deposit
    direct_transfer(app1, app2, token_address, amount, identifier=1)
    assert get_sent_transfer(channel_1_2, 0).transferred_amount == amount

    amount = int(deposit / 2.)
    identifier = 1
    async_result = app0.raiden.mediated_transfer_async(
        token_address,
        amount,
        app2.raiden.address,
        identifier,
    )
    assert async_result.wait() is False, 'Must fail, there are no routes available'

    refund_transfer = get_sent_transfer(channel_1_0, 0)
    assert isinstance(refund_transfer, RefundTransfer)
    assert refund_transfer.lock.amount == amount
