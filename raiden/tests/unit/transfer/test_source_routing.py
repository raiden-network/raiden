from raiden.messages import LockedTransfer, RouteMetadata
from raiden.tests.utils import factories
from raiden.utils.signer import LocalSigner

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

    assert locked_transfer.route_metadata.routes == [factories.HOP1, factories.HOP2]
