# -*- coding: utf-8 -*-
import gevent
import pytest

from ethereum.utils import sha3
from pyethapp.jsonrpc import address_encoder

from raiden.tests.utils.transfer import (
    assert_synched_channels,
    channel,
    pending_mediated_transfer,
)
from raiden.tests.utils.blockchain import wait_until_block
from raiden.tests.utils.network import CHAIN
from raiden.blockchain.abi import (
    CHANNELNEWBALANCE_EVENTID,
    CHANNELCLOSED_EVENTID,
    CHANNELSETTLED_EVENTID,
)
from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_channel_manager_events,
    get_all_netting_channel_events,
    get_all_registry_events,
)


def event_dicts_are_equal(dict1, dict2):
    for k, v in dict1.iteritems():
        if k not in dict2:
            return False
        if k == 'block_number':
            continue

        v2 = dict2[k]
        if isinstance(v2, basestring) and v2.startswith('0x'):
            v2 = v2[2:]
        if isinstance(v, basestring) and v.startswith('0x'):
            v = v[2:]
        if v2 != v:
            return False

    return True


@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_event_new_channel(raiden_chain, deposit, settle_timeout, events_poll_timeout):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    token_address = app0.raiden.chain.default_registry.token_addresses()[0]

    assert len(app0.raiden.channelgraphs[token_address].address_channel) == 0
    assert len(app1.raiden.channelgraphs[token_address].address_channel) == 0

    token0 = app0.raiden.chain.token(token_address)
    graph0 = app0.raiden.chain.manager_by_token(token_address)

    token1 = app1.raiden.chain.token(token_address)

    netcontract_address = graph0.new_netting_channel(
        app0.raiden.address,
        app1.raiden.address,
        settle_timeout,
    )

    netting_channel0 = app0.raiden.chain.netting_channel(netcontract_address)
    netting_channel1 = app1.raiden.chain.netting_channel(netcontract_address)

    gevent.sleep(events_poll_timeout)

    # channel is created but not opened and without funds
    assert len(app0.raiden.channelgraphs[token_address].address_channel) == 1
    assert len(app1.raiden.channelgraphs[token_address].address_channel) == 1

    channel0 = app0.raiden.channelgraphs[token_address].address_channel.values()[0]
    channel1 = app1.raiden.channelgraphs[token_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, 0, [],
        channel1, 0, [],
    )

    token0.approve(netcontract_address, deposit)
    netting_channel0.deposit(app0.raiden.address, deposit)

    gevent.sleep(events_poll_timeout)

    # channel is open but single funded
    assert len(app0.raiden.channelgraphs[token_address].address_channel) == 1
    assert len(app1.raiden.channelgraphs[token_address].address_channel) == 1

    channel0 = app0.raiden.channelgraphs[token_address].address_channel.values()[0]
    channel1 = app1.raiden.channelgraphs[token_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, deposit, [],
        channel1, 0, [],
    )

    token1.approve(netcontract_address, deposit)
    netting_channel1.deposit(app1.raiden.address, deposit)

    gevent.sleep(events_poll_timeout)

    # channel is open and funded by both participants
    assert len(app0.raiden.channelgraphs[token_address].address_channel) == 1
    assert len(app1.raiden.channelgraphs[token_address].address_channel) == 1

    channel0 = app0.raiden.channelgraphs[token_address].address_channel.values()[0]
    channel1 = app1.raiden.channelgraphs[token_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, deposit, [],
        channel1, deposit, [],
    )


@pytest.mark.parametrize('privatekey_seed', ['query_events:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
@pytest.mark.parametrize('blockchain_type', ['geth'])
@pytest.mark.parametrize('cached_genesis', [None])
def test_query_events(raiden_chain, deposit, settle_timeout, events_poll_timeout):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking

    token_address = app0.raiden.chain.default_registry.token_addresses()[0]

    assert len(app0.raiden.channelgraphs[token_address].address_channel) == 0
    assert len(app1.raiden.channelgraphs[token_address].address_channel) == 0

    token0 = app0.raiden.chain.token(token_address)
    manager0 = app0.raiden.chain.manager_by_token(token_address)

    events = get_all_registry_events(
        app0.raiden.chain,
        app0.raiden.chain.default_registry.address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest',
    )

    assert len(events) == 1
    assert event_dicts_are_equal(events[0], {
        '_event_type': 'TokenAdded',
        'channel_manager_address': address_encoder(manager0.address),
        'token_address': address_encoder(token_address),
    })

    netcontract_address = manager0.new_netting_channel(
        app0.raiden.address,
        app1.raiden.address,
        settle_timeout,
    )

    events = get_all_channel_manager_events(
        app0.raiden.chain,
        manager0.address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest',
    )

    assert len(events) == 1
    assert event_dicts_are_equal(events[0], {
        '_event_type': 'ChannelNew',
        'settle_timeout': settle_timeout,
        'netting_channel': address_encoder(netcontract_address),
        'participant1': address_encoder(app0.raiden.address),
        'participant2': address_encoder(app1.raiden.address),
    })

    netting_channel0 = app0.raiden.chain.netting_channel(netcontract_address)
    gevent.sleep(events_poll_timeout)

    # channel is created but not opened and without funds
    assert len(app0.raiden.channelgraphs[token_address].address_channel) == 1
    assert len(app1.raiden.channelgraphs[token_address].address_channel) == 1

    channel0 = app0.raiden.channelgraphs[token_address].address_channel.values()[0]
    channel1 = app1.raiden.channelgraphs[token_address].address_channel.values()[0]

    assert_synched_channels(
        channel0, 0, [],
        channel1, 0, [],
    )

    token0.approve(netcontract_address, deposit)
    netting_channel0.deposit(app0.raiden.address, deposit)

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        netting_channel_address=netcontract_address,
        from_block=0,
        to_block='latest',
    )

    events = get_all_netting_channel_events(
        app0.raiden.chain,
        netcontract_address,
        events=[CHANNELNEWBALANCE_EVENTID],
    )

    assert len(all_netting_channel_events) == 1
    assert len(events) == 1

    new_balance_event = {
        '_event_type': 'ChannelNewBalance',
        'token_address': address_encoder(token_address),
        'participant': address_encoder(app0.raiden.address),
        'balance': deposit,
        'block_number': 'ignore',
    }

    assert event_dicts_are_equal(all_netting_channel_events[-1], new_balance_event)
    assert event_dicts_are_equal(events[0], new_balance_event)

    channel0.external_state.close(app0.raiden.address, '')

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        netting_channel_address=netcontract_address,
        from_block=0,
        to_block='latest',
    )

    events = get_all_netting_channel_events(
        app0.raiden.chain,
        netcontract_address,
        events=[CHANNELCLOSED_EVENTID],
    )

    assert len(all_netting_channel_events) == 2
    assert len(events) == 1

    closed_event = {
        '_event_type': 'ChannelClosed',
        'closing_address': address_encoder(app0.raiden.address),
        'block_number': 'ignore',
    }

    assert event_dicts_are_equal(all_netting_channel_events[-1], closed_event)
    assert event_dicts_are_equal(events[0], closed_event)

    settle_expiration = app0.raiden.chain.block_number() + settle_timeout + 1
    wait_until_block(app0.raiden.chain, settle_expiration)

    channel1.external_state.settle()

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        netting_channel_address=netcontract_address,
        from_block=0,
        to_block='latest',
    )

    events = get_all_netting_channel_events(
        app0.raiden.chain,
        netcontract_address,
        events=[CHANNELSETTLED_EVENTID],
    )

    assert len(all_netting_channel_events) == 3
    assert len(events) == 1

    settled_event = {
        '_event_type': 'ChannelSettled',
        'block_number': 'ignore',
    }

    assert event_dicts_are_equal(all_netting_channel_events[-1], settled_event)
    assert event_dicts_are_equal(events[0], settled_event)


@pytest.mark.xfail(reason='out-of-gas for unlock and settle')
@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_secret_revealed(raiden_chain, deposit, settle_timeout, events_poll_timeout):
    app0, app1, app2 = raiden_chain

    token_address = app0.raiden.chain.default_registry.token_addresses()[0]
    amount = 10

    channel21 = channel(app2, app1, token_address)
    netting_channel = channel21.external_state.netting_channel

    identifier = 1
    expiration = app2.raiden.get_block_number() + settle_timeout - 3

    secret = pending_mediated_transfer(
        raiden_chain,
        token_address,
        amount,
        identifier,
        expiration,
    )
    hashlock = sha3(secret)

    gevent.sleep(.1)  # wait for the messages

    balance_proof = channel21.our_state.balance_proof
    lock = balance_proof.get_lock_by_hashlock(hashlock)
    proof = balance_proof.compute_proof_for_lock(secret, lock)

    # the secret hasn't been revealed yet (through messages)
    assert len(balance_proof.hashlock_pendinglocks) == 1
    proofs = list(balance_proof.get_known_unlocks())
    assert len(proofs) == 0

    netting_channel.close(app2.raiden.address, balance_proof.transfer, None)

    # reveal it through the blockchain (this needs to emit the SecretRevealed event)
    netting_channel.withdraw(
        app2.raiden.address,
        [proof],
    )

    settle_expiration = app0.raiden.chain.block_number() + settle_timeout
    wait_until_block(app0.raiden.chain, settle_expiration)

    channel21.settle_event.wait(timeout=10)

    assert_synched_channels(
        channel(app1, app2, token_address), deposit - amount, [],
        channel(app2, app1, token_address), deposit + amount, [],
    )

    assert_synched_channels(
        channel(app0, app1, token_address), deposit - amount, [],
        channel(app1, app2, token_address), deposit + amount, [],
    )
