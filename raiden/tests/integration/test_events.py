import gevent
import pytest

from eth_utils import to_normalized_address

from raiden.api.python import RaidenAPI
from raiden.blockchain.abi import (
    CONTRACT_MANAGER,
    EVENT_TOKEN_ADDED,
    EVENT_CHANNEL_NEW,
    EVENT_CHANNEL_CLOSED,
    EVENT_CHANNEL_NEW_BALANCE,
    EVENT_CHANNEL_SETTLED,
)
from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_channel_manager_events,
    get_all_netting_channel_events,
    get_all_registry_events,
)
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    get_channelstate,
    pending_mediated_transfer,
)
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.network import CHAIN
from raiden.transfer import views, channel
from raiden.utils import sha3


def event_dicts_are_equal(dict1, dict2):
    for k, v in dict1.items():
        if k not in dict2:
            return False
        if k == 'block_number':
            continue

        v2 = dict2[k]
        if isinstance(v2, str) and v2.startswith('0x'):
            v2 = v2[2:].lower()
        if isinstance(v, str) and v.startswith('0x'):
            v = v[2:].lower()
        if v2 != v:
            return False

    return True


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_new(raiden_chain, retry_timeout, token_addresses):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]

    channelcount0 = views.total_token_network_channels(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )

    RaidenAPI(app0.raiden).channel_open(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    gevent.sleep(retry_timeout)

    # The channel is created but without funds
    channelcount1 = views.total_token_network_channels(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )
    assert channelcount0 + 1 == channelcount1


@pytest.mark.parametrize('privatekey_seed', ['event_new_channel:{}'])
@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_channel_deposit(raiden_chain, deposit, retry_timeout, token_addresses):
    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    registry_address = app0.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    channel1 = get_channelstate(app1, app0, token_network_identifier)
    assert channel0 is None
    assert channel1 is None

    RaidenAPI(app0.raiden).channel_open(registry_address, token_address, app1.raiden.address)
    gevent.sleep(retry_timeout)

    assert_synched_channel_state(
        token_network_identifier,
        app0, 0, [],
        app1, 0, [],
    )

    RaidenAPI(app0.raiden).set_total_channel_deposit(
        registry_address,
        token_address,
        app1.raiden.address,
        deposit,
    )

    gevent.sleep(retry_timeout)

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, 0, [],
    )

    RaidenAPI(app1.raiden).set_total_channel_deposit(
        registry_address,
        token_address,
        app0.raiden.address,
        deposit,
    )

    gevent.sleep(retry_timeout)

    assert_synched_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_query_events(raiden_chain, token_addresses, deposit, settle_timeout, retry_timeout):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )

    manager0 = app0.raiden.default_registry.manager_by_token(token_address)

    channelcount0 = views.total_token_network_channels(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )

    events = get_all_registry_events(
        app0.raiden.chain,
        registry_address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest',
    )

    assert len(events) == 1
    assert events[0]['event'] == EVENT_TOKEN_ADDED
    assert event_dicts_are_equal(events[0]['args'], {
        'registry_address': to_normalized_address(registry_address),
        'channel_manager_address': to_normalized_address(manager0.address),
        'token_address': to_normalized_address(token_address),
        'block_number': 'ignore',
    })

    events = get_all_registry_events(
        app0.raiden.chain,
        app0.raiden.default_registry.address,
        events=ALL_EVENTS,
        from_block=999999998,
        to_block=999999999,
    )
    assert not events

    channel_address = RaidenAPI(app0.raiden).channel_open(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    gevent.sleep(retry_timeout * 2)

    events = get_all_channel_manager_events(
        app0.raiden.chain,
        manager0.address,
        events=ALL_EVENTS,
        from_block=0,
        to_block='latest',
    )

    assert len(events) == 1
    assert events[0]['event'] == EVENT_CHANNEL_NEW
    assert event_dicts_are_equal(events[0]['args'], {
        'registry_address': to_normalized_address(registry_address),
        'settle_timeout': settle_timeout,
        'netting_channel': to_normalized_address(channel_address),
        'participant1': to_normalized_address(app0.raiden.address),
        'participant2': to_normalized_address(app1.raiden.address),
        'block_number': 'ignore',
    })

    events = get_all_channel_manager_events(
        app0.raiden.chain,
        manager0.address,
        events=ALL_EVENTS,
        from_block=999999998,
        to_block=999999999,
    )
    assert not events

    # channel is created but not opened and without funds
    channelcount1 = views.total_token_network_channels(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )
    assert channelcount0 + 1 == channelcount1

    assert_synched_channel_state(
        token_network_identifier,
        app0, 0, [],
        app1, 0, [],
    )

    RaidenAPI(app0.raiden).set_total_channel_deposit(
        registry_address,
        token_address,
        app1.raiden.address,
        deposit,
    )

    gevent.sleep(retry_timeout * 2)

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        channel_address,
        from_block=0,
        to_block='latest',
    )

    events = get_all_netting_channel_events(
        app0.raiden.chain,
        channel_address,
        events=[CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_NEW_BALANCE)],
    )

    assert len(all_netting_channel_events) == 1
    assert len(events) == 1

    assert events[0]['event'] == EVENT_CHANNEL_NEW_BALANCE
    new_balance_event = {
        'registry_address': to_normalized_address(registry_address),
        'token_address': to_normalized_address(token_address),
        'participant': to_normalized_address(app0.raiden.address),
        'balance': deposit,
        'block_number': 'ignore',
    }

    assert event_dicts_are_equal(all_netting_channel_events[-1]['args'], new_balance_event)
    assert event_dicts_are_equal(events[0]['args'], new_balance_event)

    RaidenAPI(app0.raiden).channel_close(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    gevent.sleep(retry_timeout * 2)

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        netting_channel_address=channel_address,
        from_block=0,
        to_block='latest',
    )

    events = get_all_netting_channel_events(
        app0.raiden.chain,
        channel_address,
        events=[CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_CLOSED)],
    )

    assert len(all_netting_channel_events) == 2
    assert len(events) == 1

    assert events[0]['event'] == EVENT_CHANNEL_CLOSED
    closed_event = {
        'registry_address': to_normalized_address(registry_address),
        'closing_address': to_normalized_address(app0.raiden.address),
        'block_number': 'ignore',
    }

    assert event_dicts_are_equal(all_netting_channel_events[-1]['args'], closed_event)
    assert event_dicts_are_equal(events[0]['args'], closed_event)

    settle_expiration = app0.raiden.chain.block_number() + settle_timeout + 5
    wait_until_block(app0.raiden.chain, settle_expiration)

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        netting_channel_address=channel_address,
        from_block=0,
        to_block='latest',
    )

    events = get_all_netting_channel_events(
        app0.raiden.chain,
        channel_address,
        events=[CONTRACT_MANAGER.get_event_id(EVENT_CHANNEL_SETTLED)],
    )

    assert len(all_netting_channel_events) == 3
    assert len(events) == 1

    assert events[0]['event'] == EVENT_CHANNEL_SETTLED
    settled_event = {
        'registry_address': to_normalized_address(registry_address),
        'block_number': 'ignore',
    }

    assert event_dicts_are_equal(all_netting_channel_events[-1]['args'], settled_event)
    assert event_dicts_are_equal(events[0]['args'], settled_event)


@pytest.mark.xfail(reason='out-of-gas for unlock and settle')
@pytest.mark.parametrize('number_of_nodes', [3])
@pytest.mark.parametrize('channels_per_node', [CHAIN])
def test_secret_revealed(raiden_chain, deposit, settle_timeout, token_addresses):
    app0, app1, app2 = raiden_chain
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        views.state_from_app(app0),
        app0.raiden.default_registry.address,
        token_address,
    )

    amount = 10
    identifier = 1
    secret = pending_mediated_transfer(
        raiden_chain,
        token_network_identifier,
        amount,
        identifier,
    )
    secrethash = sha3(secret)

    gevent.sleep(.1)  # wait for the messages

    channel_state2_1 = get_channelstate(app2, app1, token_network_identifier)

    # the secret hasn't been revealed yet (through messages)

    assert len(channel_state2_1.our_state.secrethashes_to_lockedlocks) == 1
    proofs = list(channel.get_known_unlocks(channel_state2_1.our_state))
    assert not proofs

    channel.register_secret(channel_state2_1, secret, secrethash)

    # Close the channel
    netting_channel_proxy = app2.raiden.chain.netting_channel(channel_state2_1.identifier)
    netting_channel_proxy.channel_close(
        registry_address,
        channel_state2_1.partner_state.balance_proof,
    )

    # Reveal the secret through the blockchain (this needs to emit the
    # SecretRevealed event)
    for unlock_proof in channel.get_known_unlocks(channel_state2_1.partner_state):
        netting_channel_proxy.unlock(unlock_proof)

    settle_expiration = app0.raiden.chain.block_number() + settle_timeout
    wait_until_block(app0.raiden.chain, settle_expiration)

    assert_synched_channel_state(
        token_address,
        app1, deposit - amount, [],
        app2, deposit + amount, [],
    )

    assert_synched_channel_state(
        token_address,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
    )
