from raiden.messages import Processed
from raiden.tests.utils import factories
from raiden.transfer.state_change import (
    ActionCancelPayment,
    ActionTransferDirect,
    Block,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
    EventTransferReceivedSuccess,
)
from raiden.utils import sha3


ADDRESS = sha3(b'foo')[:20]
ADDRESS2 = sha3(b'boo')[:20]
ADDRESS3 = sha3(b'coo')[:20]
ADDRESS4 = sha3(b'goo')[:20]
SECRET = b'secret'
HASH = sha3(SECRET)
HASH2 = sha3(b'joo')


def test_transfer_statechange_operators():
    # pylint: disable=unneeded-not
    a = Block(2)
    b = Block(2)
    c = Block(3)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = ActionCancelPayment(2)
    b = ActionCancelPayment(2)
    c = ActionCancelPayment(3)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    token_network_identifier = factories.make_address()
    a = ActionTransferDirect(
        token_network_identifier,
        receiver_address=ADDRESS,
        payment_identifier=2,
        amount=2,
    )
    b = ActionTransferDirect(
        token_network_identifier,
        receiver_address=ADDRESS,
        payment_identifier=2,
        amount=2,
    )
    c = ActionTransferDirect(
        token_network_identifier,
        receiver_address=ADDRESS2,  # different recipient
        payment_identifier=2,
        amount=2,
    )

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c


def test_event_operators():
    a = EventTransferSentSuccess(2, 5, sha3(b'target'))
    b = EventTransferSentSuccess(2, 5, sha3(b'target'))
    c = EventTransferSentSuccess(3, 4, sha3(b'target'))
    d = EventTransferSentSuccess(3, 4, sha3(b'differenttarget'))

    # pylint: disable=unneeded-not
    assert a == b
    assert not a != b
    assert a != c
    assert not a == c
    assert not c == d

    a = EventTransferSentFailed(2, 'BECAUSE')
    b = EventTransferSentFailed(2, 'BECAUSE')
    c = EventTransferSentFailed(3, 'UNKNOWN')

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = EventTransferReceivedSuccess(2, 5, sha3(b'initiator'))
    b = EventTransferReceivedSuccess(2, 5, sha3(b'initiator'))
    c = EventTransferReceivedSuccess(3, 5, sha3(b'initiator'))
    d = EventTransferReceivedSuccess(3, 5, sha3(b'other initiator'))

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c
    assert c != d
    assert not c == d


def test_message_operators():
    message_identifier = 10
    message_identifier2 = 11

    a = Processed(message_identifier)
    b = Processed(message_identifier)
    c = Processed(message_identifier2)

    # pylint: disable=unneeded-not
    assert a == b
    assert not a != b
    assert a != c
    assert not a == c
