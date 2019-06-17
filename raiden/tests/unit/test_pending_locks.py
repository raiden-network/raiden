from raiden.transfer.channel import compute_locksroot
from raiden.transfer.state import PendingLocksState
from raiden_contracts.tests.utils import LOCKSROOT_OF_NO_LOCKS


def test_empty():
    locks = PendingLocksState(dict())
    assert compute_locksroot(locks) == LOCKSROOT_OF_NO_LOCKS
