# pylint: disable=too-many-locals,too-many-statements,too-many-lines
import random
from hashlib import sha256
from itertools import cycle

import pytest
from eth_utils import keccak

from raiden.constants import LOCKSROOT_OF_NO_LOCKS
from raiden.tests.unit.channel_state.utils import (
    make_empty_pending_locks_state,
    pending_locks_from_packed_data,
)
from raiden.tests.utils.factories import (
    HOP1,
    make_address,
    make_canonical_identifier,
    make_secret,
    make_token_network_registry_address,
)
from raiden.transfer import channel
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.mediated_transfer.mediation_fee import FeeScheduleState
from raiden.transfer.state import (
    HashTimeLockState,
    NettingChannelEndState,
    NettingChannelState,
    SuccessfulTransactionState,
    UnlockPartialProofState,
)


def test_new_end_state():
    """Test the defaults for an end state object."""
    balance1 = 101
    node_address = make_address()
    end_state = NettingChannelEndState(node_address, balance1)

    lock_secret = keccak(b"test_end_state")
    lock_secrethash = sha256(lock_secret).digest()

    assert channel.is_lock_pending(end_state, lock_secrethash) is False
    assert channel.is_lock_locked(end_state, lock_secrethash) is False
    assert channel.get_next_nonce(end_state) == 1
    assert channel.get_amount_locked(end_state) == 0
    assert compute_locksroot(end_state.pending_locks) == LOCKSROOT_OF_NO_LOCKS

    assert not end_state.secrethashes_to_lockedlocks
    assert not end_state.secrethashes_to_unlockedlocks
    assert not end_state.secrethashes_to_onchain_unlockedlocks


def test_channelstate_get_unlock_proof():
    number_of_transfers = 100
    lock_amounts = cycle([1, 3, 5, 7, 11])
    lock_secrets = [make_secret(i) for i in range(number_of_transfers)]

    block_number = 1000
    locked_amount = 0
    settle_timeout = 8
    pending_locks = make_empty_pending_locks_state()
    locked_locks = {}
    unlocked_locks = {}

    for lock_amount, lock_secret in zip(lock_amounts, lock_secrets):
        block_number += 1
        locked_amount += lock_amount

        lock_expiration = block_number + settle_timeout
        lock_secrethash = sha256(lock_secret).digest()
        lock = HashTimeLockState(lock_amount, lock_expiration, lock_secrethash)

        pending_locks.locks.append(bytes(lock.encoded))  # pylint: disable=E1101
        if random.randint(0, 1) == 0:
            locked_locks[lock_secrethash] = lock
        else:
            unlocked_locks[lock_secrethash] = UnlockPartialProofState(lock, lock_secret)

    end_state = NettingChannelEndState(HOP1, 300)
    end_state.secrethashes_to_lockedlocks = locked_locks
    end_state.secrethashes_to_unlockedlocks = unlocked_locks
    end_state.pending_locks = pending_locks

    leaves_packed = b"".join(end_state.pending_locks.locks)
    recomputed_pending_locks = pending_locks_from_packed_data(leaves_packed)
    assert len(recomputed_pending_locks.locks) == len(end_state.pending_locks.locks)

    computed_locksroot = compute_locksroot(recomputed_pending_locks)
    assert compute_locksroot(end_state.pending_locks) == computed_locksroot


def test_invalid_timeouts():
    token_address = make_address()
    token_network_address = make_address()
    token_network_registry_address = make_token_network_registry_address()
    reveal_timeout = 5
    settle_timeout = 10
    identifier = make_address()

    address1 = make_address()
    address2 = make_address()
    balance1 = 10
    balance2 = 10

    opened_transaction = SuccessfulTransactionState(1, None)
    closed_transaction = None
    settled_transaction = None

    our_state = NettingChannelEndState(address1, balance1)
    partner_state = NettingChannelEndState(address2, balance2)

    # do not allow a reveal timeout larger than the settle timeout
    with pytest.raises(ValueError):
        large_reveal_timeout = 50
        small_settle_timeout = 49

        NettingChannelState(
            canonical_identifier=make_canonical_identifier(
                token_network_address=token_network_address, channel_identifier=identifier
            ),
            token_address=token_address,
            token_network_registry_address=token_network_registry_address,
            reveal_timeout=large_reveal_timeout,
            settle_timeout=small_settle_timeout,
            our_state=our_state,
            partner_state=partner_state,
            open_transaction=opened_transaction,
            close_transaction=closed_transaction,
            settle_transaction=settled_transaction,
            fee_schedule=FeeScheduleState(),
        )

    # TypeError: 'a', [], {}
    for invalid_value in (-1, 0, 1.1, 1.0):
        with pytest.raises(ValueError):
            NettingChannelState(
                canonical_identifier=make_canonical_identifier(
                    token_network_address=token_network_address, channel_identifier=identifier
                ),
                token_address=token_address,
                token_network_registry_address=token_network_registry_address,
                reveal_timeout=invalid_value,
                settle_timeout=settle_timeout,
                our_state=our_state,
                partner_state=partner_state,
                open_transaction=opened_transaction,
                close_transaction=closed_transaction,
                settle_transaction=settled_transaction,
                fee_schedule=FeeScheduleState(),
            )

        with pytest.raises(ValueError):
            NettingChannelState(
                canonical_identifier=make_canonical_identifier(
                    token_network_address=token_network_address, channel_identifier=identifier
                ),
                token_address=token_address,
                token_network_registry_address=token_network_registry_address,
                reveal_timeout=reveal_timeout,
                settle_timeout=invalid_value,
                our_state=our_state,
                partner_state=partner_state,
                open_transaction=opened_transaction,
                close_transaction=closed_transaction,
                settle_transaction=settled_transaction,
                fee_schedule=FeeScheduleState(),
            )
