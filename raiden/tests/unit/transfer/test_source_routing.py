import random

from raiden.messages import LockedTransfer, Metadata, RefundTransfer, RouteMetadata
from raiden.routing import resolve_routes
from raiden.storage.serialization import DictSerializer
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer import mediator
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendRefundTransfer
from raiden.transfer.mediated_transfer.state_change import ReceiveTransferRefund
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


def test_mediator_skips_routes_that_have_failed():
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
    locked_transfer = factories.create(
        factories.LockedTransferSignedStateProperties(
            expiration=10,
            routes=[
                [
                    factories.UNIT_OUR_ADDRESS,
                    channels.channels[1].partner_state.address,
                    factories.UNIT_TRANSFER_TARGET,
                ],
                [
                    factories.UNIT_OUR_ADDRESS,
                    channels.channels[2].partner_state.address,
                    factories.UNIT_TRANSFER_TARGET,
                ],
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

    # now we should have a forward transfer to HOP3
    assert isinstance(events[-1], SendLockedTransfer)
    assert events[-1].recipient == factories.HOP3

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

    # now we should have a refund transfer from HOP3
    assert isinstance(events[-1], SendRefundTransfer)
