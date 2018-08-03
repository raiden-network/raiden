from copy import deepcopy

from raiden.constants import MAXIMUM_PENDING_TRANSFERS
from raiden.tests.unit.test_channelstate import (
    create_channel_from_models,
    create_model,
    make_receive_transfer_mediated,
)
from raiden.transfer.channel import handle_receive_lockedtransfer
from raiden.transfer.state import HashTimeLockState
from raiden.utils import sha3


def _channel_and_transfer(merkletree_width):

    our_model, _ = create_model(700)
    partner_model, privkey = create_model(700, merkletree_width)
    reverse_channel_state = create_channel_from_models(partner_model, our_model)

    lock_secret = sha3(b'some secret')
    lock = HashTimeLockState(30, 10, sha3(lock_secret))

    mediated_transfer = make_receive_transfer_mediated(
        reverse_channel_state,
        privkey,
        nonce=1,
        transferred_amount=0,
        lock=lock,
        merkletree_leaves=partner_model.merkletree_leaves + [lock.lockhash],
        locked_amount=lock.amount,
    )

    channel_state = deepcopy(reverse_channel_state)
    channel_state.our_state = reverse_channel_state.partner_state
    channel_state.partner_state = reverse_channel_state.our_state

    return channel_state, mediated_transfer


def test_handle_receive_lockedtransfer_enforces_transfer_limit():

    state, transfer = _channel_and_transfer(merkletree_width=MAXIMUM_PENDING_TRANSFERS - 1)
    is_valid, _, _ = handle_receive_lockedtransfer(state, transfer)
    assert is_valid

    state, transfer = _channel_and_transfer(merkletree_width=MAXIMUM_PENDING_TRANSFERS)
    is_valid, _, _ = handle_receive_lockedtransfer(state, transfer)
    assert not is_valid
