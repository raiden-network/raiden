from typing import Dict, List

import gevent
import pytest
from eth_utils import is_list_like, to_checksum_address
from web3.utils.events import construct_event_topic_set

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.blockchain.events import (
    ALL_EVENTS,
    get_all_netting_channel_events,
    get_contract_events,
    get_token_network_events,
    get_token_network_registry_events,
)
from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.network.blockchain_service import BlockChainService
from raiden.tests.utils.events import must_have_event
from raiden.tests.utils.geth import wait_until_block
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import HoldOffChainSecretRequest
from raiden.tests.utils.transfer import assert_synced_channel_state, get_channelstate
from raiden.transfer import channel, views
from raiden.utils import sha3
from raiden.utils.typing import Address, BlockSpecification, ChannelID
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)
from raiden_contracts.contract_manager import ContractManager


def get_netting_channel_closed_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        contract_manager: ContractManager,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    closed_event_abi = contract_manager.get_event_abi(
        CONTRACT_TOKEN_NETWORK,
        ChannelEvent.CLOSED,
    )

    topic_set = construct_event_topic_set(
        event_abi=closed_event_abi,
        arguments={'channel_identifier': netting_channel_identifier},
    )

    if len(topic_set) == 1 and is_list_like(topic_set[0]):
        topics = topic_set[0]
    else:
        topics = topic_set

    return get_contract_events(
        chain=chain,
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        contract_address=token_network_address,
        topics=topics,
        from_block=from_block,
        to_block=to_block,
    )


def get_netting_channel_deposit_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        contract_manager: ContractManager,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    deposit_event_abi = contract_manager.get_event_abi(
        CONTRACT_TOKEN_NETWORK,
        ChannelEvent.DEPOSIT,
    )
    topic_set = construct_event_topic_set(
        event_abi=deposit_event_abi,
        arguments={'channel_identifier': netting_channel_identifier},
    )

    if len(topic_set) == 1 and is_list_like(topic_set[0]):
        topics = topic_set[0]
    else:
        topics = topic_set

    return get_contract_events(
        chain,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        topics,
        from_block,
        to_block,
    )


def get_netting_channel_settled_events(
        chain: BlockChainService,
        token_network_address: Address,
        netting_channel_identifier: ChannelID,
        contract_manager: ContractManager,
        from_block: BlockSpecification = GENESIS_BLOCK_NUMBER,
        to_block: BlockSpecification = 'latest',
) -> List[Dict]:
    settled_event_abi = contract_manager.get_event_abi(
        CONTRACT_TOKEN_NETWORK,
        ChannelEvent.SETTLED,
    )
    topic_set = construct_event_topic_set(
        event_abi=settled_event_abi,
        arguments={'channel_identifier': netting_channel_identifier},
    )

    if len(topic_set) == 1 and is_list_like(topic_set[0]):
        topics = topic_set[0]
    else:
        topics = topic_set

    return get_contract_events(
        chain,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        token_network_address,
        topics,
        from_block,
        to_block,
    )


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

    assert_synced_channel_state(
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

    assert_synced_channel_state(
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

    assert_synced_channel_state(
        token_network_identifier,
        app0, deposit, [],
        app1, deposit, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
@pytest.mark.parametrize('channels_per_node', [0])
def test_query_events(
        raiden_chain,
        token_addresses,
        deposit,
        settle_timeout,
        retry_timeout,
        contract_manager,
):
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
        chain=app0.raiden.chain,
        token_network_registry_address=registry_address,
        contract_manager=contract_manager,
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
        chain=app0.raiden.chain,
        token_network_registry_address=app0.raiden.default_registry.address,
        contract_manager=contract_manager,
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
        chain=app0.raiden.chain,
        token_network_address=manager0.address,
        contract_manager=contract_manager,
        events=ALL_EVENTS,
    )

    _event = must_have_event(
        events,
        {
            'event': ChannelEvent.OPENED,
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
        chain=app0.raiden.chain,
        token_network_address=manager0.address,
        contract_manager=contract_manager,
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

    assert_synced_channel_state(
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
        chain=app0.raiden.chain,
        token_network_address=token_network_identifier,
        netting_channel_identifier=channel_id,
        contract_manager=app0.raiden.contract_manager,
    )

    deposit_events = get_netting_channel_deposit_events(
        chain=app0.raiden.chain,
        token_network_address=token_network_identifier,
        netting_channel_identifier=channel_id,
        contract_manager=contract_manager,
    )

    total_deposit_event = {
        'event': ChannelEvent.DEPOSIT,
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
        chain=app0.raiden.chain,
        token_network_address=token_network_identifier,
        netting_channel_identifier=channel_id,
        contract_manager=app0.raiden.contract_manager,
    )

    closed_events = get_netting_channel_closed_events(
        chain=app0.raiden.chain,
        token_network_address=token_network_identifier,
        netting_channel_identifier=channel_id,
        contract_manager=contract_manager,
    )

    closed_event = {
        'event': ChannelEvent.CLOSED,
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
        chain=app0.raiden.chain,
        token_network_address=token_network_identifier,
        netting_channel_identifier=channel_id,
        contract_manager=app0.raiden.contract_manager,
    )

    settled_events = get_netting_channel_settled_events(
        chain=app0.raiden.chain,
        token_network_address=token_network_identifier,
        netting_channel_identifier=channel_id,
        contract_manager=contract_manager,
    )

    settled_event = {
        'event': ChannelEvent.SETTLED,
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

    hold_event_handler = HoldOffChainSecretRequest()
    app2.raiden.raiden_event_handler = hold_event_handler

    amount = 10
    identifier = 1
    target = app2.raiden.address
    secret = sha3(target)
    secrethash = sha3(secret)

    hold_event_handler.hold_secretrequest_for(secret)

    app0.raiden.start_mediated_transfer_with_secret(
        token_network_identifier,
        amount,
        target,
        identifier,
        secret,
    )

    gevent.sleep(.1)  # wait for the messages

    # The secret hasn't been revealed yet
    channel_state2_1 = get_channelstate(app2, app1, token_network_identifier)
    assert len(channel_state2_1.our_state.secrethashes_to_lockedlocks) == 1

    channel.register_offchain_secret(channel_state2_1, secret, secrethash)

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

    assert_synced_channel_state(
        token_address,
        app1, deposit - amount, [],
        app2, deposit + amount, [],
    )

    assert_synced_channel_state(
        token_address,
        app0, deposit - amount, [],
        app1, deposit + amount, [],
    )


@pytest.mark.parametrize('number_of_nodes', [2])
def test_clear_closed_queue(raiden_network, token_addresses, deposit):
    """ Closing a channel clears the respective message queue. """
    app0, app1 = raiden_network
    registry_address = app0.raiden.default_registry.address
    token_address = token_addresses[0]
    chain_state0 = views.state_from_app(app0)
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state0,
        app0.raiden.default_registry.address,
        token_address,
    )
    token_network = views.get_token_network_by_identifier(
        chain_state0,
        token_network_identifier,
    )

    channel_identifier = get_channelstate(app0, app1, token_network_identifier).identifier

    assert channel_identifier in token_network.partneraddresses_to_channels[
        app1.raiden.address
    ]

    app1.raiden.transport.stop()
    app1.raiden.transport.get()

    # make a direct transfer to ensure the nodes have communicated
    amount = 10
    payment_identifier = 1337
    app0.raiden.direct_transfer_async(
        token_network_identifier,
        amount,
        app1.raiden.address,
        identifier=payment_identifier,
    )

    # assert the specific queue is present
    chain_state0 = views.state_from_app(app0)
    queues0 = views.get_all_messagequeues(chain_state=chain_state0)
    assert [
        (queue_id, queue)
        for queue_id, queue in queues0.items()
        if queue_id.recipient == app1.raiden.address and
        queue_id.channel_identifier == channel_identifier and queue
    ]

    # A ChannelClose event will be generated, this will be polled by both apps
    RaidenAPI(app0.raiden).channel_close(
        registry_address,
        token_address,
        app1.raiden.address,
    )

    exception = ValueError('Could not get close event')
    with gevent.Timeout(seconds=30, exception=exception):
        waiting.wait_for_close(
            app0.raiden,
            registry_address,
            token_address,
            [channel_identifier],
            app0.raiden.alarm.sleep_time,
        )

    # assert all queues with this partner are gone or empty
    chain_state0 = views.state_from_app(app0)
    queues0 = views.get_all_messagequeues(chain_state=chain_state0)
    assert not [
        (queue_id, queue)
        for queue_id, queue in queues0.items()
        if queue_id.recipient == app1.raiden.address and queue
    ]

    chain_state1 = views.state_from_app(app1)
    queues1 = views.get_all_messagequeues(chain_state=chain_state1)
    assert not [
        (queue_id, queue)
        for queue_id, queue in queues1.items()
        if queue_id.recipient == app0.raiden.address and queue
    ]
