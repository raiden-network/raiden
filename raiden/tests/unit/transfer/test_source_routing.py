import random

from raiden.messages.metadata import Metadata, RouteMetadata
from raiden.messages.transfers import LockedTransfer, RefundTransfer
from raiden.routing import resolve_routes
from raiden.storage.serialization import DictSerializer
from raiden.tests.utils import factories
from raiden.tests.utils.events import search_for_item
from raiden.transfer import views
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendRefundTransfer
from raiden.transfer.mediated_transfer.state_change import (
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.node import handle_init_initiator, state_transition
from raiden.utils.signer import LocalSigner, recover

PARTNER_PRIVKEY, PARTNER_ADDRESS = factories.make_privkey_address()
PRIVKEY, ADDRESS = factories.make_privkey_address()
signer = LocalSigner(PRIVKEY)


def test_can_create_refund_transfer_messages():
    refund_transfer = factories.create(factories.RefundTransferProperties())

    assert refund_transfer is not None
    assert isinstance(refund_transfer, RefundTransfer)
    assert isinstance(refund_transfer.metadata, Metadata)
    assert len(refund_transfer.metadata.routes) == 1


def test_route_metadata_hashing():
    properties = factories.RouteMetadataProperties()
    one_route_metadata = factories.create(properties)
    assert isinstance(one_route_metadata, RouteMetadata)
    one_hash = one_route_metadata.hash

    another_route_metadata = factories.create(properties)
    another_hash = another_route_metadata.hash

    assert one_hash == another_hash, "route metadata with same routes do not match"

    inverted_route_metadata = factories.create(
        factories.RouteMetadataProperties(route=[factories.HOP2, factories.HOP1])
    )

    inverted_route_hash = inverted_route_metadata.hash

    assert one_hash != inverted_route_hash, "route metadata with inverted routes still match"


def test_metadata_hashing():
    properties = factories.MetadataProperties()
    one_metadata = factories.create(properties)
    assert isinstance(one_metadata, Metadata)
    one_hash = one_metadata.hash

    another_metadata = factories.create(properties)
    another_hash = another_metadata.hash

    assert one_hash == another_hash, "route metadata with same routes do not match"

    inverted_route_metadata = factories.create(
        factories.RouteMetadataProperties(route=[factories.HOP2, factories.HOP1])
    )

    metadata_with_inverted_route = factories.create(
        factories.MetadataProperties(routes=[inverted_route_metadata])
    )

    inverted_route_hash = metadata_with_inverted_route.hash

    assert one_hash != inverted_route_hash, "route metadata with inverted routes still match"


def test_locked_transfer_with_metadata():
    locked_transfer = factories.create(factories.LockedTransferProperties())
    assert isinstance(locked_transfer, LockedTransfer)
    assert isinstance(locked_transfer.metadata, Metadata)

    # pylint: disable=E1101
    assert locked_transfer.metadata.routes[0].route == [factories.HOP1, factories.HOP2]


def test_locked_transfer_additional_hash_contains_route_metadata_hash():
    one_locked_transfer = factories.create(factories.LockedTransferProperties())
    route_metadata = factories.create(
        factories.RouteMetadataProperties(route=[factories.HOP2, factories.HOP1])
    )
    another_locked_transfer = factories.create(
        factories.LockedTransferProperties(
            metadata=factories.create(factories.MetadataProperties(routes=[route_metadata]))
        )
    )

    assert (
        one_locked_transfer.message_hash != another_locked_transfer.message_hash
    ), "LockedTransfers with different routes should have different message hashes"


def test_changing_route_metadata_will_invalidate_lock_transfer_signature():
    one_locked_transfer = factories.create(
        factories.LockedTransferProperties(sender=ADDRESS, pkey=PRIVKEY)
    )

    new_route_metadata = factories.create(
        factories.RouteMetadataProperties(route=[factories.HOP2, factories.HOP1])
    )

    new_metadata = factories.create(factories.Metadata(routes=[new_route_metadata]))

    assert ADDRESS == recover(
        one_locked_transfer._data_to_sign(), one_locked_transfer.signature
    ), "signature does not match signer address"

    one_locked_transfer.metadata = new_metadata

    assert ADDRESS != recover(
        one_locked_transfer._data_to_sign(), one_locked_transfer.signature
    ), "signature should not be valid after data being altered"


def test_can_round_trip_serialize_locked_transfer():
    locked_transfer = factories.create(
        factories.LockedTransferProperties(sender=ADDRESS, pkey=PRIVKEY)
    )

    as_dict = DictSerializer.serialize(locked_transfer)
    assert DictSerializer.deserialize(as_dict) == locked_transfer


def test_resolve_routes(netting_channel_state, chain_state, token_network_state):
    route_metadata = factories.create(
        factories.RouteMetadataProperties(
            route=[
                netting_channel_state.our_state.address,
                netting_channel_state.partner_state.address,
            ]
        )
    )

    route_states = resolve_routes(
        routes=[route_metadata],
        token_network_address=token_network_state.address,
        chain_state=chain_state,
    )

    msg = "route resolved with wrong channel id"
    channel_id = netting_channel_state.canonical_identifier.channel_identifier
    assert route_states[0].forward_channel_id == channel_id, msg


def test_initiator_skips_used_routes():
    defaults = factories.NettingChannelStateProperties(
        our_state=factories.NettingChannelEndStateProperties.OUR_STATE,
        partner_state=factories.NettingChannelEndStateProperties(balance=10),
        open_transaction=factories.TransactionExecutionStatusProperties(
            started_block_number=1, finished_block_number=2, result="success"
        ),
    )
    properties = [
        factories.NettingChannelStateProperties(
            partner_state=factories.NettingChannelEndStateProperties(
                privatekey=factories.HOP1_KEY, address=factories.HOP1
            )
        )
    ]
    test_chain_state = factories.make_chain_state(
        number_of_channels=1, properties=properties, defaults=defaults
    )
    channels = test_chain_state.channel_set

    bob = channels.channels[0].partner_state.address

    routes = [[factories.UNIT_OUR_ADDRESS, bob, factories.UNIT_TRANSFER_TARGET]]

    transfer = factories.create(
        factories.TransferDescriptionProperties(
            initiator=factories.UNIT_OUR_ADDRESS, target=factories.UNIT_TRANSFER_TARGET
        )
    )
    init_action = factories.initiator_make_init_action(
        channels=channels, routes=routes, transfer=transfer
    )
    transition_result = handle_init_initiator(
        chain_state=test_chain_state.chain_state, state_change=init_action
    )

    chain_state = transition_result.new_state

    assert transfer.secrethash in chain_state.payment_mapping.secrethashes_to_task

    initiator_task = chain_state.payment_mapping.secrethashes_to_task[transfer.secrethash]
    initiator_state = initiator_task.manager_state

    assert len(initiator_state.routes) == 1, "Should have one route"
    assert len(initiator_state.routes[0].route) == 3, "Route should not be pruned"
    assert initiator_state.routes[0].route == routes[0], "Should have test route"

    events = transition_result.events

    assert isinstance(events[-1], SendLockedTransfer)

    locked_transfer = initiator_state.initiator_transfers[transfer.secrethash].transfer

    received_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            expiration=locked_transfer.lock.expiration,
            payment_identifier=locked_transfer.payment_identifier,
            canonical_identifier=locked_transfer.balance_proof.canonical_identifier,
            initiator=factories.UNIT_OUR_ADDRESS,
            sender=bob,
            pkey=factories.HOP1_KEY,
            message_identifier=factories.make_message_identifier(),
            routes=[],
            secret=transfer.secret,
        )
    )

    role = views.get_transfer_role(
        chain_state=chain_state, secrethash=locked_transfer.lock.secrethash
    )

    assert role == "initiator", "Should keep initiator role"

    refund_state_change = ReceiveTransferRefundCancelRoute(
        transfer=received_transfer,
        balance_proof=received_transfer.balance_proof,
        sender=received_transfer.balance_proof.sender,  # pylint: disable=no-member
        secret=factories.make_secret(),
        is_reroute_allowed=True,
    )

    iteration = state_transition(chain_state=chain_state, state_change=refund_state_change)

    assert search_for_item(iteration.events, SendLockedTransfer, {}) is None


def test_mediator_skips_used_routes():
    prng = random.Random()
    block_number = 3
    defaults = factories.NettingChannelStateProperties(
        our_state=factories.NettingChannelEndStateProperties.OUR_STATE,
        partner_state=factories.NettingChannelEndStateProperties(balance=10),
        open_transaction=factories.TransactionExecutionStatusProperties(
            started_block_number=1, finished_block_number=2, result="success"
        ),
    )
    properties = [
        factories.NettingChannelStateProperties(
            partner_state=factories.NettingChannelEndStateProperties(
                privatekey=factories.HOP1_KEY, address=factories.HOP1
            )
        ),
        factories.NettingChannelStateProperties(
            partner_state=factories.NettingChannelEndStateProperties(
                privatekey=factories.HOP2_KEY, address=factories.HOP2
            )
        ),
        factories.NettingChannelStateProperties(
            partner_state=factories.NettingChannelEndStateProperties(
                privatekey=factories.HOP3_KEY, address=factories.HOP3
            )
        ),
    ]
    channels = factories.make_channel_set(
        properties=properties, number_of_channels=3, defaults=defaults
    )
    bob = channels.channels[1].partner_state.address
    charlie = channels.channels[2].partner_state.address
    dave = factories.make_address()
    eric = factories.make_address()
    locked_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            expiration=10,
            routes=[
                [factories.UNIT_OUR_ADDRESS, bob, dave, factories.UNIT_TRANSFER_TARGET],
                [factories.UNIT_OUR_ADDRESS, bob, eric, factories.UNIT_TRANSFER_TARGET],
                [factories.UNIT_OUR_ADDRESS, charlie, eric, factories.UNIT_TRANSFER_TARGET],
            ],
            canonical_identifier=channels.channels[0].canonical_identifier,
            pkey=factories.HOP1_KEY,
            sender=factories.HOP1,
        )
    )
    init_action = factories.mediator_make_init_action(channels=channels, transfer=locked_transfer)
    nodeaddresses_to_networkstates = {
        channel.partner_state.address: "reachable" for channel in channels.channels
    }

    transition_result = mediator.handle_init(
        state_change=init_action,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=prng,
        block_number=block_number,
    )
    mediator_state = transition_result.new_state
    events = transition_result.events
    assert mediator_state is not None
    assert events

    assert len(mediator_state.routes) == 3
    assert mediator_state.routes[0].route[1] == bob
    assert mediator_state.routes[1].route[1] == bob
    assert mediator_state.routes[2].route[1] == charlie
    # now we receive a refund from whoever we forwarded to (should be HOP2)
    assert isinstance(events[-1], SendLockedTransfer)
    assert events[-1].recipient == factories.HOP2

    last_pair = mediator_state.transfers_pair[-1]
    canonical_identifier = last_pair.payee_transfer.balance_proof.canonical_identifier
    lock_expiration = last_pair.payee_transfer.lock.expiration
    payment_identifier = last_pair.payee_transfer.payment_identifier

    received_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            expiration=lock_expiration,
            payment_identifier=payment_identifier,
            canonical_identifier=canonical_identifier,
            sender=factories.HOP2,
            pkey=factories.HOP2_KEY,
            message_identifier=factories.make_message_identifier(),
        )
    )

    refund_state_change = ReceiveTransferRefund(
        transfer=received_transfer,
        balance_proof=received_transfer.balance_proof,
        sender=received_transfer.balance_proof.sender,  # pylint: disable=no-member
    )
    transition_result = mediator.handle_refundtransfer(
        mediator_state=mediator_state,
        mediator_state_change=refund_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=prng,
        block_number=block_number,
    )

    mediator_state = transition_result.new_state
    events = transition_result.events
    assert mediator_state is not None
    assert events
    assert mediator_state.transfers_pair[-1].payee_address == charlie

    # now we should have a forward transfer to HOP3
    assert isinstance(events[-1], SendLockedTransfer)
    assert events[-1].recipient == factories.HOP3

    # now we will receive a refund from HOP3

    last_pair = mediator_state.transfers_pair[-1]
    canonical_identifier = last_pair.payee_transfer.balance_proof.canonical_identifier
    lock_expiration = last_pair.payee_transfer.lock.expiration
    payment_identifier = last_pair.payee_transfer.payment_identifier

    received_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            expiration=lock_expiration,
            payment_identifier=payment_identifier,
            canonical_identifier=canonical_identifier,
            sender=factories.HOP3,
            pkey=factories.HOP3_KEY,
            message_identifier=factories.make_message_identifier(),
        )
    )

    refund_state_change = ReceiveTransferRefund(
        transfer=received_transfer,
        balance_proof=received_transfer.balance_proof,
        sender=received_transfer.balance_proof.sender,  # pylint: disable=no-member
    )

    transition_result = mediator.handle_refundtransfer(
        mediator_state=mediator_state,
        mediator_state_change=refund_state_change,
        channelidentifiers_to_channels=channels.channel_map,
        nodeaddresses_to_networkstates=nodeaddresses_to_networkstates,
        pseudo_random_generator=prng,
        block_number=block_number,
    )

    mediator_state = transition_result.new_state
    events = transition_result.events
    assert mediator_state is not None
    assert events

    # no other routes available, so refund HOP1
    assert isinstance(events[-1], SendRefundTransfer)
    assert events[-1].recipient == factories.HOP1
