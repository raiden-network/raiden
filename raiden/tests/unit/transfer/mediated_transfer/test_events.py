from raiden.storage.serialization import JSONSerializer
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.events import SendRefundTransfer


def test_send_refund_transfer_contains_balance_proof():
    recipient = factories.make_address()
    transfer = factories.create(factories.LockedTransferUnsignedStateProperties())
    message_identifier = 1
    event = SendRefundTransfer(
        recipient=recipient,
        message_identifier=message_identifier,
        transfer=transfer,
        canonical_identifier=factories.make_canonical_identifier(),
    )

    assert hasattr(event, "balance_proof")
    assert JSONSerializer.deserialize(JSONSerializer.serialize(event)) == event
