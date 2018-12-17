from raiden.tests.utils.factories import make_address, make_channel_identifier, make_transfer
from raiden.transfer.mediated_transfer.events import SendRefundTransfer


def test_send_refund_transfer_contains_balance_proof():
    recipient = make_address()
    transfer = make_transfer()
    message_identifier = 1
    channel_identifier = make_channel_identifier()
    event = SendRefundTransfer(
        recipient=recipient,
        channel_identifier=channel_identifier,
        message_identifier=message_identifier,
        transfer=transfer,
    )

    assert hasattr(event, 'balance_proof')
    assert SendRefundTransfer.from_dict(event.to_dict()) == event
