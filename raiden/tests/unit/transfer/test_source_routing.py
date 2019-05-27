from raiden.messages import LockedTransfer, RouteMetadata
from raiden.routing import resolve_route
from raiden.storage.serialization import DictSerializer
from raiden.tests.utils import factories
from raiden.utils.signer import LocalSigner, recover

PARTNER_PRIVKEY, PARTNER_ADDRESS = factories.make_privkey_address()
PRIVKEY, ADDRESS = factories.make_privkey_address()
signer = LocalSigner(PRIVKEY)


def test_route_metadata_hashing():
    properties = factories.RouteMetadataProperties()
    one_route_metadata = factories.create(properties)
    assert isinstance(one_route_metadata, RouteMetadata)
    one_hash = one_route_metadata.hash

    another_route_metadata = factories.create(properties)
    another_hash = another_route_metadata.hash

    assert one_hash == another_hash, "route metadata with same routes do not match"

    inverted_route_metadata = factories.create(
        factories.RouteMetadataProperties(routes=[factories.HOP2, factories.HOP1])
    )

    inverted_route_hash = inverted_route_metadata.hash

    assert one_hash != inverted_route_hash, "route metadata with inverted routes still match"


def test_locked_transfer_with_route_metadata():
    locked_transfer = factories.create(factories.LockedTransferProperties())
    assert isinstance(locked_transfer, LockedTransfer)
    assert isinstance(locked_transfer.route_metadata, RouteMetadata)

    # pylint: disable=E1101
    assert locked_transfer.route_metadata.routes == [factories.HOP1, factories.HOP2]


def test_locked_transfer_additional_hash_contains_route_metadata_hash():
    one_locked_transfer = factories.create(factories.LockedTransferProperties())
    another_locked_transfer = factories.create(
        factories.LockedTransferProperties(
            route_metadata=factories.create(
                factories.RouteMetadataProperties(routes=[factories.HOP2, factories.HOP1])
            )
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
        factories.RouteMetadataProperties(routes=[factories.HOP2, factories.HOP1])
    )

    assert ADDRESS == recover(
        one_locked_transfer._data_to_sign(), one_locked_transfer.signature
    ), "signature does not match signer address"

    one_locked_transfer.route_metadata = new_route_metadata

    assert ADDRESS != recover(
        one_locked_transfer._data_to_sign(), one_locked_transfer.signature
    ), "signature should not be valid after data being altered"


def test_can_round_trip_serialize_locked_transfer():
    locked_transfer = factories.create(
        factories.LockedTransferProperties(sender=ADDRESS, pkey=PRIVKEY)
    )

    as_dict = DictSerializer.serialize(locked_transfer)
    assert DictSerializer.deserialize(as_dict) == locked_transfer


def test_resolve_route(netting_channel_state, chain_state, token_network_state):
    route_metadata = factories.create(
        factories.RouteMetadataProperties(
            routes=[
                netting_channel_state.our_state.address,
                netting_channel_state.partner_state.address,
            ]
        )
    )

    route_state = resolve_route(
        route_metadata=route_metadata,
        token_network_address=token_network_state.address,
        chain_state=chain_state,
    )

    msg = "route resolved with wrong channel id"
    channel_id = netting_channel_state.canonical_identifier.channel_identifier
    assert route_state.forward_channel_id == channel_id, msg


def test_mediator_forwards_pruned_route():
    pass
