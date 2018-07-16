import gevent
import pytest

from eth_utils import to_checksum_address
from raiden_contracts.constants import (
    EVENT_CHANNEL_CLOSED,
    EVENT_CHANNEL_DEPOSIT,
    EVENT_CHANNEL_OPENED,
    EVENT_CHANNEL_SETTLED,
    EVENT_TOKEN_NETWORK_CREATED,
)

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_netting_channel_events,
    get_netting_channel_closed_events,
    get_netting_channel_deposit_events,
    get_netting_channel_settled_events,
    get_token_network_events,
    get_token_network_registry_events,
)
from raiden.tests.utils.events import must_have_event
from raiden.tests.utils.transfer import (
    assert_synched_channel_state,
    get_channelstate,
    pending_mediated_transfer,
)
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.network import CHAIN
from raiden.transfer import views, channel
from raiden.utils import sha3


def wait_both_channel_open(
        app0,
        app1,
        registry_address,
        token_address,
        retry_timeout,
):
    waiting.wait_for_newchannel(
        app1.raiden,
        registry_address,
        token_address,
        app0.raiden.address,
        retry_timeout,
    )
    waiting.wait_for_newchannel(
        app0.raiden,
        registry_address,
        token_address,
        app1.raiden.address,
        retry_timeout,
    )


def wait_both_channel_deposit(
        app_deposit,
        app_partner,
        registry_address,
        token_address,
        total_deposit,
        retry_timeout,
):
    waiting.wait_for_participant_newbalance(
        app_deposit.raiden,
        registry_address,
        token_address,
        app_partner.raiden.address,
        app_deposit.raiden.address,
        total_deposit,
        retry_timeout,
    )

    waiting.wait_for_participant_newbalance(
        app_partner.raiden,
        registry_address,
        token_address,
        app_deposit.raiden.address,
        app_deposit.raiden.address,
        total_deposit,
        retry_timeout,
    )


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

    wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout)

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

    RaidenAPI(app0.raiden).channel_open(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout)

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

    wait_both_channel_deposit(
        app0,
        app1,
        registry_address,
        token_address,
        deposit,
        retry_timeout,
    )

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

    wait_both_channel_deposit(
        app1,
        app0,
        registry_address,
        token_address,
        deposit,
        retry_timeout,
    )

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

    token_network_address = app0.raiden.default_registry.get_token_network(token_address)
    manager0 = app0.raiden.chain.token_network(token_network_address)

    channelcount0 = views.total_token_network_channels(
        views.state_from_app(app0),
        registry_address,
        token_address,
    )

    events = get_token_network_registry_events(
        app0.raiden.chain,
        registry_address,
        events=ALL_EVENTS,
    )

    assert must_have_event(
        events,
        {
            'event': EVENT_TOKEN_NETWORK_CREATED,
            'args': {
                'token_network_address': to_checksum_address(manager0.address),
                'token_address': to_checksum_address(token_address),
            },
        },
    )

    events = get_token_network_registry_events(
        app0.raiden.chain,
        app0.raiden.default_registry.address,
        events=ALL_EVENTS,
        from_block=999999998,
        to_block=999999999,
    )
    assert not events

    RaidenAPI(app0.raiden).channel_open(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout)

    events = get_token_network_events(
        app0.raiden.chain,
        manager0.address,
        events=ALL_EVENTS,
    )

    _event = must_have_event(
        events,
        {
            'event': EVENT_CHANNEL_OPENED,
            'args': {
                'participant1': to_checksum_address(app0.raiden.address),
                'participant2': to_checksum_address(app1.raiden.address),
                'settle_timeout': settle_timeout,
            },
        },
    )
    assert _event
    channel_id = _event['args']['channel_identifier']

    events = get_token_network_events(
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

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        token_network_identifier,
        channel_id,
    )

    deposit_events = get_netting_channel_deposit_events(
        app0.raiden.chain,
        token_network_identifier,
        channel_id,
    )

    total_deposit_event = {
        'event': EVENT_CHANNEL_DEPOSIT,
        'args': {
            'participant': to_checksum_address(app0.raiden.address),
            'total_deposit': deposit,
            'channel_identifier': channel_id,
        },
    }
    assert must_have_event(deposit_events, total_deposit_event)
    assert must_have_event(all_netting_channel_events, total_deposit_event)

    RaidenAPI(app0.raiden).channel_close(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        token_network_identifier,
        channel_id,
    )

    closed_events = get_netting_channel_closed_events(
        app0.raiden.chain,
        token_network_identifier,
        channel_id,
    )

    closed_event = {
        'event': EVENT_CHANNEL_CLOSED,
        'args': {
            'channel_identifier': channel_id,
            'closing_participant': to_checksum_address(app0.raiden.address),
        },
    }
    assert must_have_event(closed_events, closed_event)
    assert must_have_event(all_netting_channel_events, closed_event)

    settle_expiration = app0.raiden.chain.block_number() + settle_timeout + 5
    wait_until_block(app0.raiden.chain, settle_expiration)

    all_netting_channel_events = get_all_netting_channel_events(
        app0.raiden.chain,
        token_network_identifier,
        channel_id,
    )

    settled_events = get_netting_channel_settled_events(
        app0.raiden.chain,
        token_network_identifier,
        channel_id,
    )

    settled_event = {
        'event': EVENT_CHANNEL_SETTLED,
        'args': {
            'channel_identifier': channel_id,
        },
    }
    assert must_have_event(settled_events, settled_event)
    assert must_have_event(all_netting_channel_events, settled_event)


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

    # The secret hasn't been revealed yet
    channel_state2_1 = get_channelstate(app2, app1, token_network_identifier)
    assert len(channel_state2_1.our_state.secrethashes_to_lockedlocks) == 1

    channel.register_secret(channel_state2_1, secret, secrethash)

    # Close the channel
    # This needs to register the secrets on chain
    netting_channel_proxy = app2.raiden.chain.payment_channel(
        token_network_identifier,
        channel_state2_1.identifier,
    )
    netting_channel_proxy.channel_close(
        registry_address,
        channel_state2_1.partner_state.balance_proof,
    )

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
