# pylint: disable=too-many-locals,too-many-statements,too-many-lines
from collections import namedtuple

from raiden.messages.transfers import Lock
from raiden.tests.utils.factories import (
    BalanceProofProperties,
    NettingChannelEndStateProperties,
    NettingChannelStateProperties,
    create,
    make_lock,
    make_privkey_address,
    make_signed_balance_proof_from_unsigned,
)
from raiden.transfer import channel
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.state import (
    PendingLocksState,
    SuccessfulTransactionState,
    make_empty_pending_locks_state,
)
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import EncodedData

PartnerStateModel = namedtuple(
    "PartnerStateModel",
    (
        "participant_address",
        "amount_locked",
        "balance",
        "distributable",
        "next_nonce",
        "pending_locks",
        "contract_balance",
    ),
)


def assert_partner_state(end_state, partner_state, model):
    """Checks that the stored data for both ends correspond to the model."""
    assert end_state.address == model.participant_address
    assert channel.get_amount_locked(end_state) == model.amount_locked
    assert channel.get_balance(end_state, partner_state) == model.balance
    assert channel.get_distributable(end_state, partner_state) == model.distributable
    assert channel.get_next_nonce(end_state) == model.next_nonce
    assert set(end_state.pending_locks.locks) == set(model.pending_locks)
    assert end_state.contract_balance == model.contract_balance


def create_model(balance, num_pending_locks=0):
    privkey, address = make_privkey_address()

    locks = [make_lock() for _ in range(num_pending_locks)]
    pending_locks = [bytes(lock.encoded) for lock in locks]

    our_model = PartnerStateModel(
        participant_address=address,
        amount_locked=0,
        balance=balance,
        distributable=balance,
        next_nonce=len(pending_locks) + 1,
        pending_locks=pending_locks,
        contract_balance=balance,
    )

    return our_model, privkey


def create_channel_from_models(our_model, partner_model, partner_pkey):
    """Utility to instantiate state objects used throughout the tests."""
    channel_state = create(
        NettingChannelStateProperties(
            reveal_timeout=10,
            settle_timeout=100,
            our_state=NettingChannelEndStateProperties(
                address=our_model.participant_address,
                balance=our_model.balance,
                pending_locks=PendingLocksState(our_model.pending_locks),
            ),
            partner_state=NettingChannelEndStateProperties(
                address=partner_model.participant_address,
                balance=partner_model.balance,
                pending_locks=PendingLocksState(partner_model.pending_locks),
            ),
            open_transaction=SuccessfulTransactionState(finished_block_number=1),
        )
    )

    our_nonce = our_model.next_nonce - 1
    assert our_nonce >= 0, "nonce cannot be negative"
    if our_nonce > 0:
        our_unsigned = create(
            BalanceProofProperties(
                nonce=our_nonce,
                transferred_amount=0,
                locked_amount=len(our_model.pending_locks),
                locksroot=compute_locksroot(channel_state.our_state.pending_locks),
                canonical_identifier=channel_state.canonical_identifier,
            )
        )
        channel_state.our_state.nonce = our_unsigned.nonce
    else:
        our_unsigned = None

    partner_nonce = partner_model.next_nonce - 1
    assert partner_nonce >= 0, "nonce cannot be negative"
    if partner_nonce > 0:
        partner_unsigned = create(
            BalanceProofProperties(
                nonce=partner_nonce,
                transferred_amount=0,
                locked_amount=len(partner_model.pending_locks),
                locksroot=compute_locksroot(channel_state.partner_state.pending_locks),
                canonical_identifier=channel_state.canonical_identifier,
            )
        )

        partner_signed = make_signed_balance_proof_from_unsigned(
            partner_unsigned, LocalSigner(partner_pkey)
        )
        channel_state.partner_state.nonce = partner_signed.nonce
    else:
        partner_signed = None

    channel_state.our_state.balance_proof = our_unsigned
    channel_state.partner_state.balance_proof = partner_signed

    assert channel_state.our_total_deposit == our_model.contract_balance
    assert channel_state.partner_total_deposit == partner_model.contract_balance

    assert_partner_state(channel_state.our_state, channel_state.partner_state, our_model)

    assert_partner_state(channel_state.partner_state, channel_state.our_state, partner_model)
    return channel_state


def pending_locks_from_packed_data(packed: bytes) -> PendingLocksState:
    number_of_bytes = len(packed)
    locks = make_empty_pending_locks_state()
    for i in range(0, number_of_bytes, 96):
        lock = Lock.from_bytes(packed[i : i + 96])
        locks.locks.append(EncodedData(lock.as_bytes))  # pylint: disable=E1101
    return locks
