from raiden.messages import LockedTransfer, RouteMetadata
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
