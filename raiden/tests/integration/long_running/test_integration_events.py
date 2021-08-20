from unittest.mock import patch

import gevent
import pytest
from eth_utils import keccak
from web3._utils.events import construct_event_topic_set

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.blockchain.events import get_all_netting_channel_events, get_contract_events
from raiden.constants import BLOCK_ID_LATEST, GENESIS_BLOCK_NUMBER
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.token_network import TokenNetwork
from raiden.raiden_service import RaidenService
from raiden.settings import (
    DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS,
    INTERNAL_ROUTING_DEFAULT_FEE_PERC,
)
from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import must_have_event, search_for_item, wait_for_state_change
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.protocol import HoldRaidenEventHandler
from raiden.tests.utils.transfer import (
    assert_synced_channel_state,
    block_offset_timeout,
    create_route_state_for_route,
    get_channelstate,
    watch_for_unlock_failures,
)
from raiden.transfer import views
from raiden.transfer.events import ContractSendChannelClose
from raiden.transfer.mediated_transfer.events import SendLockedTransfer
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal
from raiden.transfer.state import BalanceProofSignedState
from raiden.transfer.state_change import ContractReceiveChannelBatchUnlock
from raiden.utils.formatting import to_checksum_address
from raiden.utils.secrethash import sha256_secrethash
from raiden.utils.typing import (
    Address,
    Balance,
    BlockIdentifier,
    BlockNumber,
    ChannelID,
    Dict,
    FeeAmount,
    List,
    PaymentAmount,
    PaymentID,
    Secret,
    TargetAddress,
    TokenNetworkAddress,
)
from raiden.waiting import wait_until
from raiden_contracts.constants import (
    CONTRACT_TOKEN_NETWORK,
    CONTRACT_TOKEN_NETWORK_REGISTRY,
    EVENT_TOKEN_NETWORK_CREATED,
    ChannelEvent,
)
from raiden_contracts.contract_manager import ContractManager


def get_netting_channel_closed_events(
    proxy_manager: ProxyManager,
    token_network_address: TokenNetworkAddress,
    netting_channel_identifier: ChannelID,
    contract_manager: ContractManager,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:
    closed_event_abi = contract_manager.get_event_abi(CONTRACT_TOKEN_NETWORK, ChannelEvent.CLOSED)

    topic_set = construct_event_topic_set(
        event_abi=closed_event_abi,
        abi_codec=proxy_manager.client.web3.codec,
        arguments={"channel_identifier": netting_channel_identifier},
    )

    return get_contract_events(
        proxy_manager=proxy_manager,
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        contract_address=Address(token_network_address),
        topics=topic_set,  # type: ignore
        from_block=from_block,
        to_block=to_block,
    )


def get_netting_channel_deposit_events(
    proxy_manager: ProxyManager,
    token_network_address: TokenNetworkAddress,
    netting_channel_identifier: ChannelID,
    contract_manager: ContractManager,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:
    deposit_event_abi = contract_manager.get_event_abi(
        CONTRACT_TOKEN_NETWORK, ChannelEvent.DEPOSIT
    )
    topic_set = construct_event_topic_set(
        event_abi=deposit_event_abi,
        abi_codec=proxy_manager.client.web3.codec,
        arguments={"channel_identifier": netting_channel_identifier},
    )

    return get_contract_events(
        proxy_manager,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        Address(token_network_address),
        topic_set,  # type: ignore
        from_block,
        to_block,
    )


def get_netting_channel_settled_events(
    proxy_manager: ProxyManager,
    token_network_address: TokenNetworkAddress,
    netting_channel_identifier: ChannelID,
    contract_manager: ContractManager,
    from_block: BlockIdentifier = GENESIS_BLOCK_NUMBER,
    to_block: BlockIdentifier = BLOCK_ID_LATEST,
) -> List[Dict]:
    settled_event_abi = contract_manager.get_event_abi(
        CONTRACT_TOKEN_NETWORK, ChannelEvent.SETTLED
    )
    topic_set = construct_event_topic_set(
        event_abi=settled_event_abi,
        abi_codec=proxy_manager.client.web3.codec,
        arguments={"channel_identifier": netting_channel_identifier},
    )

    return get_contract_events(
        proxy_manager,
        contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        Address(token_network_address),
        topic_set,  # type: ignore
        from_block,
        to_block,
    )


def wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout):
    waiting.wait_for_newchannel(app1, registry_address, token_address, app0.address, retry_timeout)
    waiting.wait_for_newchannel(app0, registry_address, token_address, app1.address, retry_timeout)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_channel_new(raiden_chain: List[RaidenService], retry_timeout, token_addresses):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]

    channelcount0 = views.total_token_network_channels(
        views.state_from_raiden(app0), registry_address, token_address
    )

    RaidenAPI(app0).channel_open(registry_address, token_address, app1.address)

    wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout)

    # The channel is created but without funds
    channelcount1 = views.total_token_network_channels(
        views.state_from_raiden(app0), registry_address, token_address
    )
    assert channelcount0 + 1 == channelcount1


@raise_on_failure
@pytest.mark.parametrize("privatekey_seed", ["event_new_channel:{}"])
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_channel_deposit(
    raiden_chain: List[RaidenService], deposit, retry_timeout, token_addresses
):
    app0, app1 = raiden_chain
    token_address = token_addresses[0]

    registry_address = app0.default_registry.address
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    channel0 = views.get_channelstate_by_token_network_and_partner(
        views.state_from_raiden(app0), token_network_address, app1.address
    )
    channel1 = views.get_channelstate_by_token_network_and_partner(
        views.state_from_raiden(app0), token_network_address, app1.address
    )
    assert channel0 is None
    assert channel1 is None

    RaidenAPI(app0).channel_open(registry_address, token_address, app1.address)

    timeout_seconds = 15
    exception = RuntimeError(f"Did not see the channels open within {timeout_seconds} seconds")
    with gevent.Timeout(seconds=timeout_seconds, exception=exception):
        wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout)

    assert_synced_channel_state(token_network_address, app0, Balance(0), [], app1, Balance(0), [])

    RaidenAPI(app0).set_total_channel_deposit(
        registry_address, token_address, app1.address, deposit
    )

    exception = RuntimeError(f"Did not see the channel deposit within {timeout_seconds} seconds")
    with gevent.Timeout(seconds=timeout_seconds, exception=exception):
        waiting.wait_single_channel_deposit(
            app0, app1, registry_address, token_address, deposit, retry_timeout
        )

    assert_synced_channel_state(token_network_address, app0, deposit, [], app1, Balance(0), [])

    RaidenAPI(app1).set_total_channel_deposit(
        registry_address, token_address, app0.address, deposit
    )

    with gevent.Timeout(seconds=timeout_seconds, exception=exception):
        waiting.wait_single_channel_deposit(
            app1, app0, registry_address, token_address, deposit, retry_timeout
        )

    assert_synced_channel_state(token_network_address, app0, deposit, [], app1, deposit, [])


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
@pytest.mark.parametrize("channels_per_node", [0])
def test_query_events(
    raiden_chain: List[RaidenService],
    token_addresses,
    deposit,
    settle_timeout,
    retry_timeout,
    contract_manager,
    blockchain_type,
):
    app0, app1 = raiden_chain  # pylint: disable=unbalanced-tuple-unpacking
    registry_address = app0.default_registry.address
    token_address = token_addresses[0]

    token_network_address = app0.default_registry.get_token_network(token_address, BLOCK_ID_LATEST)

    assert token_network_address
    manager0 = app0.proxy_manager.token_network(token_network_address, BLOCK_ID_LATEST)

    channelcount0 = views.total_token_network_channels(
        views.state_from_raiden(app0), registry_address, token_address
    )

    events = get_contract_events(
        proxy_manager=app0.proxy_manager,
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
        contract_address=Address(registry_address),
    )

    assert must_have_event(
        events,
        {
            "event": EVENT_TOKEN_NETWORK_CREATED,
            "args": {
                "token_network_address": to_checksum_address(manager0.address),
                "token_address": to_checksum_address(token_address),
            },
        },
    )

    if blockchain_type == "geth":
        # FIXME: This is apparently meant to verify that querying nonexisting blocks
        # returns an empty list, which is not true for parity.
        events = get_contract_events(
            proxy_manager=app0.proxy_manager,
            abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK_REGISTRY),
            contract_address=Address(app0.default_registry.address),
            from_block=BlockNumber(999999998),
            to_block=BlockNumber(999999999),
        )
        assert not events

    RaidenAPI(app0).channel_open(registry_address, token_address, app1.address)

    wait_both_channel_open(app0, app1, registry_address, token_address, retry_timeout)

    events = get_contract_events(
        proxy_manager=app0.proxy_manager,
        abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
        contract_address=Address(manager0.address),
    )

    _event = must_have_event(
        events,
        {
            "event": ChannelEvent.OPENED,
            "args": {
                "participant1": to_checksum_address(app0.address),
                "participant2": to_checksum_address(app1.address),
                "settle_timeout": settle_timeout,
            },
        },
    )
    assert _event
    channel_id = _event["args"]["channel_identifier"]

    if blockchain_type == "geth":
        # see above
        events = get_contract_events(
            proxy_manager=app0.proxy_manager,
            abi=contract_manager.get_contract_abi(CONTRACT_TOKEN_NETWORK),
            contract_address=Address(manager0.address),
            from_block=BlockNumber(999999998),
            to_block=BlockNumber(999999999),
        )
        assert not events

    # channel is created but not opened and without funds
    channelcount1 = views.total_token_network_channels(
        views.state_from_raiden(app0), registry_address, token_address
    )
    assert channelcount0 + 1 == channelcount1

    assert_synced_channel_state(token_network_address, app0, Balance(0), [], app1, Balance(0), [])

    RaidenAPI(app0).set_total_channel_deposit(
        registry_address, token_address, app1.address, deposit
    )

    all_netting_channel_events = get_all_netting_channel_events(
        proxy_manager=app0.proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_id,
        contract_manager=app0.contract_manager,
    )

    deposit_events = get_netting_channel_deposit_events(
        proxy_manager=app0.proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_id,
        contract_manager=contract_manager,
    )

    total_deposit_event = {
        "event": ChannelEvent.DEPOSIT,
        "args": {
            "participant": to_checksum_address(app0.address),
            "total_deposit": deposit,
            "channel_identifier": channel_id,
        },
    }
    assert must_have_event(deposit_events, total_deposit_event)
    assert must_have_event(all_netting_channel_events, total_deposit_event)

    RaidenAPI(app0).channel_close(registry_address, token_address, app1.address)

    all_netting_channel_events = get_all_netting_channel_events(
        proxy_manager=app0.proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_id,
        contract_manager=app0.contract_manager,
    )

    closed_events = get_netting_channel_closed_events(
        proxy_manager=app0.proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_id,
        contract_manager=contract_manager,
    )

    closed_event = {
        "event": ChannelEvent.CLOSED,
        "args": {
            "channel_identifier": channel_id,
            "closing_participant": to_checksum_address(app0.address),
        },
    }
    assert must_have_event(closed_events, closed_event)
    assert must_have_event(all_netting_channel_events, closed_event)

    settle_expiration = app0.rpc_client.block_number() + settle_timeout + 5
    app0.proxy_manager.client.wait_until_block(target_block_number=settle_expiration)

    all_netting_channel_events = get_all_netting_channel_events(
        proxy_manager=app0.proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_id,
        contract_manager=app0.contract_manager,
    )

    settled_events = get_netting_channel_settled_events(
        proxy_manager=app0.proxy_manager,
        token_network_address=token_network_address,
        netting_channel_identifier=channel_id,
        contract_manager=contract_manager,
    )

    settled_event = {"event": ChannelEvent.SETTLED, "args": {"channel_identifier": channel_id}}
    assert must_have_event(settled_events, settled_event)
    assert must_have_event(all_netting_channel_events, settled_event)


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [3])
@pytest.mark.parametrize("channels_per_node", [CHAIN])
def test_secret_revealed_on_chain(
    raiden_chain: List[RaidenService],
    deposit,
    settle_timeout,
    token_addresses,
    retry_interval_initial,
):
    """A node must reveal the secret on-chain if it's known and the channel is closed."""
    app0, app1, app2 = raiden_chain
    token_address = token_addresses[0]
    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_raiden(app0), app0.default_registry.address, token_address
    )
    assert token_network_address

    amount = PaymentAmount(10)
    identifier = PaymentID(1)
    target = TargetAddress(app2.address)
    secret, secrethash = factories.make_secret_with_hash()

    # Reveal the secret, but do not unlock it off-chain
    app1_hold_event_handler = app1.raiden_event_handler

    msg = "test apps must have HoldRaidenEventHandler set"
    assert isinstance(app1_hold_event_handler, HoldRaidenEventHandler), msg

    app1_hold_event_handler.hold_unlock_for(secrethash=secrethash)

    app0.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=amount,
        target=target,
        identifier=identifier,
        secret=secret,
        route_states=[
            create_route_state_for_route(
                apps=raiden_chain,
                token_address=token_address,
                fee_estimate=FeeAmount(round(INTERNAL_ROUTING_DEFAULT_FEE_PERC * amount)),
            )
        ],
    )

    with watch_for_unlock_failures(*raiden_chain), block_offset_timeout(app0):
        wait_for_state_change(
            app2, ReceiveSecretReveal, {"secrethash": secrethash}, retry_interval_initial
        )

    channel_state2_1 = get_channelstate(app2, app1, token_network_address)
    pending_lock = channel_state2_1.partner_state.secrethashes_to_unlockedlocks.get(secrethash)
    msg = "The lock must be registered in unlocked locks since the secret is known"
    assert pending_lock is not None, msg

    # The channels are out-of-sync. app1 has sent the unlock, however we are
    # intercepting it and app2 has not received the updated balance proof

    # Mock the contract's unlock method to find out who is doing the unlock
    unlockers = []
    orig_unlock = TokenNetwork.unlock

    def _mocked_unlock(self: TokenNetwork, *args, **kwargs):
        unlockers.append(self.node_address)
        return orig_unlock(self, *args, **kwargs)

    with patch.object(TokenNetwork, "unlock", _mocked_unlock):
        # Close the channel. This must register the secret on chain
        balance_proof = channel_state2_1.partner_state.balance_proof
        assert isinstance(balance_proof, BalanceProofSignedState)
        channel_close_event = ContractSendChannelClose(
            canonical_identifier=channel_state2_1.canonical_identifier,
            balance_proof=balance_proof,
            triggered_by_block_hash=app0.rpc_client.blockhash_from_blocknumber(BLOCK_ID_LATEST),
        )

        assert app2.wal, "test apps must be started by the fixture."
        current_state = views.state_from_raiden(app2)

        app2.raiden_event_handler.on_raiden_events(
            raiden=app2, chain_state=current_state, events=[channel_close_event]
        )

        settle_expiration = (
            app0.rpc_client.block_number() + settle_timeout + DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
        )
        app0.proxy_manager.client.wait_until_block(target_block_number=settle_expiration)

        # TODO:
        # - assert on the transferred amounts on-chain (for settle and unlock)

        # The channel app0-app1 should continue with the protocol off-chain, once
        # the secret is released on-chain by app2
        assert_synced_channel_state(
            token_network_address, app0, deposit - amount, [], app1, deposit + amount, []
        )

        with watch_for_unlock_failures(*raiden_chain), gevent.Timeout(40):
            wait_for_state_change(
                app1,
                ContractReceiveChannelBatchUnlock,
                {},
                retry_interval_initial,
            )

    # Check that only the correct node did the unlock. Prevents regression of
    # https://github.com/raiden-network/raiden/issues/6706
    assert unlockers == [app2.address]


@raise_on_failure
@pytest.mark.parametrize("number_of_nodes", [2])
def test_clear_closed_queue(raiden_network: List[RaidenService], token_addresses, network_wait):
    """Closing a channel clears the respective message queue."""
    app0, app1 = raiden_network

    hold_event_handler = app1.raiden_event_handler
    assert isinstance(hold_event_handler, HoldRaidenEventHandler)

    registry_address = app0.default_registry.address
    token_address = token_addresses[0]
    chain_state0 = views.state_from_raiden(app0)
    token_network_address = views.get_token_network_address_by_token_address(
        chain_state0, app0.default_registry.address, token_address
    )
    assert token_network_address
    token_network = views.get_token_network_by_address(chain_state0, token_network_address)
    assert token_network

    channel_identifier = get_channelstate(app0, app1, token_network_address).identifier

    assert channel_identifier in token_network.partneraddresses_to_channelidentifiers[app1.address]

    target = app1.address
    secret = Secret(keccak(target))
    secrethash = sha256_secrethash(secret)
    hold_event_handler.hold_secretrequest_for(secrethash=secrethash)

    # make an unconfirmed transfer to ensure the nodes have communicated
    amount = PaymentAmount(10)
    payment_identifier = PaymentID(1337)
    app0.mediated_transfer_async(
        token_network_address=token_network_address,
        amount=amount,
        target=TargetAddress(target),
        identifier=payment_identifier,
        secret=secret,
        route_states=[create_route_state_for_route([app0, app1], token_address)],
    )

    app1.transport.stop()
    app1.transport.greenlet.get()

    # make sure to wait until the queue is created
    def has_initiator_events():
        assert app0.wal, "raiden server must have been started"
        initiator_events = app0.wal.storage.get_events()
        return search_for_item(initiator_events, SendLockedTransfer, {})

    assert wait_until(has_initiator_events, network_wait)

    # assert the specific queue is present
    chain_state0 = views.state_from_raiden(app0)
    queues0 = views.get_all_messagequeues(chain_state=chain_state0)
    assert [
        (queue_id, queue)
        for queue_id, queue in queues0.items()
        if queue_id.recipient == app1.address
        and queue_id.canonical_identifier.channel_identifier == channel_identifier
        and queue
    ]

    # A ChannelClose event will be generated, this will be polled by both apps
    RaidenAPI(app0).channel_close(registry_address, token_address, app1.address, coop_settle=False)

    with block_offset_timeout(app0, "Could not get close event"):
        waiting.wait_for_close(
            app0,
            registry_address,
            token_address,
            [channel_identifier],
            app0.alarm.sleep_time,
        )

    # assert all queues with this partner are gone or empty
    chain_state0 = views.state_from_raiden(app0)
    queues0 = views.get_all_messagequeues(chain_state=chain_state0)
    assert not [
        (queue_id, queue)
        for queue_id, queue in queues0.items()
        if queue_id.recipient == app1.address and queue
    ]

    chain_state1 = views.state_from_raiden(app1)
    queues1 = views.get_all_messagequeues(chain_state=chain_state1)
    assert not [
        (queue_id, queue)
        for queue_id, queue in queues1.items()
        if queue_id.recipient == app0.address and queue
    ]
