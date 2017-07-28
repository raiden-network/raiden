# -*- coding: utf-8 -*-
from raiden.utils import sha3
from raiden.transfer.state_change import (
    ActionCancelTransfer,
    ActionTransferDirect,
    Block,
    ReceiveTransferDirect,
)
from raiden.transfer.state import (
    RouteState,
    RoutesState,
)
from raiden.transfer.events import (
    EventTransferSentSuccess,
    EventTransferSentFailed,
    EventTransferReceivedSuccess,
)
from raiden.network.protocol import (
    NODE_NETWORK_REACHABLE,
    NODE_NETWORK_UNREACHABLE,
    NODE_NETWORK_UNKNOWN
)
from raiden.transfer.mediated_transfer.state import LockedTransferState
from raiden.messages import Ack
from raiden.network.channelgraph import RouteOrderedItem


ADDRESS = sha3('foo')[:20]
ADDRESS2 = sha3('boo')[:20]
ADDRESS3 = sha3('coo')[:20]
ADDRESS4 = sha3('goo')[:20]
SECRET = 'secret'
HASH = sha3(SECRET)
HASH2 = sha3('joo')


def test_transfer_statechange_operators():
    a = Block(2)
    b = Block(2)
    c = Block(3)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = ActionCancelTransfer(2)
    b = ActionCancelTransfer(2)
    c = ActionCancelTransfer(3)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = ActionTransferDirect(2, 2, ADDRESS, ADDRESS)
    b = ActionTransferDirect(2, 2, ADDRESS, ADDRESS)
    c = ActionTransferDirect(3, 4, ADDRESS, ADDRESS2)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = ReceiveTransferDirect(2, 2, ADDRESS, ADDRESS)
    b = ReceiveTransferDirect(2, 2, ADDRESS, ADDRESS)
    c = ReceiveTransferDirect(3, 4, ADDRESS, ADDRESS2)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c


def test_state_operators():
    a_route = RouteState('opened', ADDRESS, ADDRESS2, 5, 5, 5, 5)
    b_route = RouteState('opened', ADDRESS, ADDRESS2, 5, 5, 5, 5)
    c_route = RouteState('closed', ADDRESS3, ADDRESS2, 1, 2, 3, 4)

    assert a_route == b_route
    assert not a_route != b_route
    assert a_route != c_route
    assert not a_route == c_route

    d_route = RouteState('opened', ADDRESS4, ADDRESS, 1, 2, 3, 4)
    a = RoutesState([a_route, d_route])
    b = RoutesState([a_route, d_route])
    c = RoutesState([a_route, c_route])

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = LockedTransferState(1, 2, ADDRESS, ADDRESS2, ADDRESS3, 4, HASH, 'secret')
    b = LockedTransferState(1, 2, ADDRESS, ADDRESS2, ADDRESS3, 4, HASH, 'secret')
    c = LockedTransferState(2, 4, ADDRESS3, ADDRESS4, ADDRESS, 4, HASH, 'secret')

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c


def test_event_operators():
    a = EventTransferSentSuccess(2)
    b = EventTransferSentSuccess(2)
    c = EventTransferSentSuccess(3)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = EventTransferSentFailed(2, 'BECAUSE')
    b = EventTransferSentFailed(2, 'BECAUSE')
    c = EventTransferSentFailed(3, 'UNKNOWN')

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c

    a = EventTransferReceivedSuccess(2, 5, sha3('initiator'))
    b = EventTransferReceivedSuccess(2, 5, sha3('initiator'))
    c = EventTransferReceivedSuccess(3, 5, sha3('initiator'))
    d = EventTransferReceivedSuccess(3, 5, sha3('other initiator'))

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c
    assert c != d
    assert not c == d


def test_message_operators():
    a = Ack(ADDRESS, HASH)
    b = Ack(ADDRESS, HASH)
    c = Ack(ADDRESS2, HASH2)

    assert a == b
    assert not a != b
    assert a != c
    assert not a == c


def test_route_ordered_item_operators():
    a_route = RouteState('opened', ADDRESS, ADDRESS2, 5, 5, 5, 5)

    item1 = RouteOrderedItem(0, NODE_NETWORK_REACHABLE, a_route)
    item2 = RouteOrderedItem(0, NODE_NETWORK_REACHABLE, a_route)
    item3 = RouteOrderedItem(1, NODE_NETWORK_REACHABLE, a_route)
    item4 = RouteOrderedItem(1, NODE_NETWORK_UNKNOWN, a_route)
    item5 = RouteOrderedItem(1, NODE_NETWORK_UNREACHABLE, a_route)

    assert item1 == item2
    assert not item1 != item2
    assert item1 != item3
    assert not item1 == item3

    assert item1 < item3
    assert item3 > item1

    assert item3 < item4
    assert item1 < item4
    assert item4 < item5
