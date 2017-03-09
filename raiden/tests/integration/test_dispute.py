# -*- coding: utf-8 -*-
# pylint: disable=too-many-locals,too-many-statements
import pytest

from raiden.tests.utils.blockchain import wait_until_block
from raiden.utils import privatekey_to_address


@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('number_of_nodes', [2])
def test_automatic_dispute(raiden_network, deposit, settle_timeout):
    app0, app1 = raiden_network

    graph0 = app0.raiden.channelgraphs.values()[0]
    graph1 = app1.raiden.channelgraphs.values()[0]

    channel0 = graph0.partneraddress_channel.values()[0]
    channel1 = graph1.partneraddress_channel.values()[0]

    privatekey0 = app0.raiden.private_key
    privatekey1 = app1.raiden.private_key

    address0 = privatekey_to_address(privatekey0.private_key)
    address1 = privatekey_to_address(privatekey1.private_key)

    token = app0.raiden.chain.token(channel0.token_address)
    initial_balance0 = token.balance_of(address0)
    initial_balance1 = token.balance_of(address1)

    # Alice sends Bob 10 tokens
    amount_alice1 = 10
    direct_transfer = channel0.create_directtransfer(
        amount_alice1,
        identifier=1,
    )
    direct_transfer.sign(privatekey0, address0)
    channel0.register_transfer(direct_transfer)
    channel1.register_transfer(direct_transfer)
    alice_old_transaction = direct_transfer

    # Bob sends Alice 50 tokens
    amount_bob1 = 50
    direct_transfer = channel1.create_directtransfer(
        amount_bob1,
        identifier=1,
    )
    direct_transfer.sign(privatekey1, address1)
    channel0.register_transfer(direct_transfer)
    channel1.register_transfer(direct_transfer)
    bob_last_transaction = direct_transfer

    # Finally Alice sends Bob 60 tokens
    amount_alice2 = 60
    direct_transfer = channel0.create_directtransfer(
        amount_alice2,
        identifier=1,
    )
    direct_transfer.sign(privatekey0, address0)
    channel0.register_transfer(direct_transfer)
    channel1.register_transfer(direct_transfer)

    # Then Alice attempts to close the channel with an older transfer of hers
    channel0.external_state.close(
        None,
        bob_last_transaction,
        alice_old_transaction
    )
    chain0 = app0.raiden.chain
    wait_until_block(chain0, chain0.block_number() + 1)

    assert channel0.close_event.wait(timeout=25)
    assert channel1.close_event.wait(timeout=25)

    assert channel0.external_state.closed_block != 0
    assert channel1.external_state.closed_block != 0

    # wait until the settle timeout has passed
    settle_expiration = chain0.block_number() + settle_timeout
    wait_until_block(chain0, settle_expiration)

    # the settle event must be set
    assert channel0.settle_event.wait(timeout=60)
    assert channel1.settle_event.wait(timeout=60)

    # check that the channel is properly settled and that Bob's client
    # automatically called updateTransfer() to reflect the actual transactions
    assert channel0.external_state.settled_block != 0
    assert channel1.external_state.settled_block != 0
    assert token.balance_of(channel0.external_state.netting_channel.address) == 0
    total_alice = amount_alice1 + amount_alice2
    total_bob = amount_bob1
    assert token.balance_of(address0) == initial_balance0 + deposit - total_alice + total_bob
    assert token.balance_of(address1) == initial_balance1 + deposit + total_alice - total_bob
