from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.events import SendRefundTransfer


def test_send_refund_transfer_contains_balance_proof():
    recipient = factories.make_address()
    transfer = factories.create(factories.LockedTransferUnsignedStateProperties())
    message_identifier = 1
    channel_identifier = factories.make_channel_identifier()
    event = SendRefundTransfer(
        recipient=recipient,
        channel_identifier=channel_identifier,
        message_identifier=message_identifier,
        transfer=transfer,
    )

    assert hasattr(event, "balance_proof")
    assert SendRefundTransfer.from_dict(event.to_dict()) == event
