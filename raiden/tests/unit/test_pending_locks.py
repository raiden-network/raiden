from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.state import PendingLocksState


def test_empty():
    locks = PendingLocksState(list())
    assert compute_locksroot(locks) == LOCKSROOT_OF_NO_LOCKS
