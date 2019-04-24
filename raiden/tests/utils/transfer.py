""" Utilities to make and assert transfers. """
import random

import gevent
from gevent.timeout import Timeout

from raiden.app import App
from raiden.constants import UINT64_MAX
from raiden.message_handler import MessageHandler
from raiden.messages import LockedTransfer, LockExpired, Message, Unlock
from raiden.tests.utils.factories import make_address
from raiden.tests.utils.protocol import WaitForMessage
from raiden.transfer import channel, views
from raiden.transfer.mediated_transfer.state import (
    LockedTransferSignedState,
    lockedtransfersigned_from_message,
)
from raiden.transfer.mediated_transfer.state_change import ReceiveLockExpired
from raiden.transfer.merkle_tree import MERKLEROOT, compute_layers
from raiden.transfer.state import (
    CHANNEL_STATE_OPENED,
    HashTimeLockState,
    MerkleTreeState,
    NettingChannelState,
    balanceproof_from_envelope,
    make_empty_merkle_tree,
)
from raiden.utils import lpex, pex, random_secret, sha3
from raiden.utils.signer import LocalSigner, Signer
from raiden.utils.typing import (
    Balance,
    Callable,
    ChainID,
    FeeAmount,
    InitiatorAddress,
    Keccak256,
    List,
    LockedAmount,
    Nonce,
    Optional,
    PaymentAmount,
    PaymentID,
    Secret,
    TargetAddress,
    TokenAddress,
    TokenAmount,
    TokenNetworkID,
)


def sign_and_inject(message: Message, signer: Signer, app: App) -> None:
    """Sign the message with key and inject it directly in the app transport layer."""
    message.sign(signer)
    MessageHandler().on_message(app.raiden, message)


def get_channelstate(
        app0: App,
        app1: App,
        token_network_identifier: TokenNetworkID,
) -> NettingChannelState:
    channel_state = views.get_channelstate_by_token_network_and_partner(
        views.state_from_app(app0),
        token_network_identifier,
        app1.raiden.address,
    )
    return channel_state


def transfer(
        initiator_app: App,
        target_app: App,
        token_address: TokenAddress,
        amount: PaymentAmount,
        identifier: PaymentID,
        fee: FeeAmount = 0,
        timeout: float = 10,
) -> None:
    """ Nice to read shortcut to make successful LockedTransfer.

    Note:
        Only the initiator and target are synched.
    """
    assert identifier is not None, 'The identifier must be provided'
    assert isinstance(target_app.raiden.message_handler, WaitForMessage)

    wait_for_unlock = target_app.raiden.message_handler.wait_for_message(
        Unlock,
        {'payment_identifier': identifier},
    )

    payment_network_identifier = initiator_app.raiden.default_registry.address
    token_network_identifier = views.get_token_network_identifier_by_token_address(
        chain_state=views.state_from_app(initiator_app),
        payment_network_id=payment_network_identifier,
        token_address=token_address,
    )
    payment_status = initiator_app.raiden.mediated_transfer_async(
        token_network_identifier=token_network_identifier,
        amount=amount,
        target=target_app.raiden.address,
        identifier=identifier,
        fee=fee,
    )

    with Timeout(seconds=timeout):
        wait_for_unlock.get()
        msg = (
            f'transfer from {pex(initiator_app.raiden.address)} '
            f'to {pex(target_app.raiden.address)} failed.'
        )
        assert payment_status.payment_done.get(), msg


def transfer_and_assert_path(
        path: List[App],
        token_address: TokenAddress,
        amount: PaymentAmount,
        identifier: PaymentID,
        fee: FeeAmount = 0,
        timeout: float = 10,
) -> None:
    """ Nice to read shortcut to make successful LockedTransfer.

    Note:
        This utility *does not enforce the path*, however it does check the
        provided path is used in totality. It's the responsability of the
        caller to ensure the path will be used. All nodes in `path` are
        synched.
    """
    assert identifier is not None, 'The identifier must be provided'
    secret = random_secret()

    first_app = path[0]
    payment_network_identifier = first_app.raiden.default_registry.address
    token_network_address = views.get_token_network_identifier_by_token_address(
        chain_state=views.state_from_app(first_app),
        payment_network_id=payment_network_identifier,
        token_address=token_address,
    )

    for app in path:
        assert isinstance(app.raiden.message_handler, WaitForMessage)

        msg = (
            'The apps must be on the same payment network'
        )
        assert app.raiden.default_registry.address == payment_network_identifier, msg

        app_token_network_address = views.get_token_network_identifier_by_token_address(
            chain_state=views.state_from_app(app),
            payment_network_id=payment_network_identifier,
            token_address=token_address,
        )

        msg = (
            'The apps must be synchronized with the blockchain'
        )
        assert token_network_address == app_token_network_address, msg

    pairs = zip(path[:-1], path[1:])
    receiving = list()
    for from_app, to_app in pairs:
        from_channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=views.state_from_app(from_app),
            token_network_id=token_network_address,
            partner_address=to_app.raiden.address,
        )
        to_channel_state = views.get_channelstate_by_token_network_and_partner(
            chain_state=views.state_from_app(to_app),
            token_network_id=token_network_address,
            partner_address=from_app.raiden.address,
        )

        msg = (
            f'{pex(from_app.raiden.address)} does not have a channel with '
            f'{pex(to_app.raiden.address)} needed to transfer through the '
            f'path {lpex(app.raiden.address for app in path)}.'
        )
        assert from_channel_state, msg
        assert to_channel_state, msg

        msg = (
            f'channel among {pex(from_app.raiden.address)} and '
            f'{pex(to_app.raiden.address)} must be open to be used for a '
            f'transfer'
        )
        assert channel.get_status(from_channel_state) == CHANNEL_STATE_OPENED, msg
        assert channel.get_status(to_channel_state) == CHANNEL_STATE_OPENED, msg

        receiving.append((to_app, to_channel_state.identifier))

    results = [
        app.raiden.message_handler.wait_for_message(
            Unlock,
            {
                'channel_identifier': channel_identifier,
                'token_network_address': token_network_address,
                'payment_identifier': identifier,
                'secret': secret,
            },
        )
        for app, channel_identifier in receiving
    ]

    last_app = path[-1]
    payment_status = first_app.raiden.start_mediated_transfer_with_secret(
        token_network_identifier=token_network_address,
        amount=amount,
        fee=fee,
        target=last_app.raiden.address,
        identifier=identifier,
        secret=secret,
    )

    with Timeout(seconds=timeout):
        gevent.wait(results)
        msg = (
            f'transfer from {pex(first_app.raiden.address)} '
            f'to {pex(last_app.raiden.address)} failed.'
        )
        assert payment_status.payment_done.get(), msg


def assert_synced_channel_state(
        token_network_identifier: TokenNetworkID,
        app0: App,
        balance0: Balance,
        pending_locks0: List[HashTimeLockState],
        app1: App,
        balance1: Balance,
        pending_locks1: List[HashTimeLockState],
) -> None:
    """ Assert the values of two synced channels.

    Note:
        This assert does not work for an intermediate state, where one message
        hasn't been delivered yet or has been completely lost."""
    # pylint: disable=too-many-arguments

    channel0 = get_channelstate(app0, app1, token_network_identifier)
    channel1 = get_channelstate(app1, app0, token_network_identifier)

    assert channel0.our_state.contract_balance == channel1.partner_state.contract_balance
    assert channel0.partner_state.contract_balance == channel1.our_state.contract_balance

    total_token = channel0.our_state.contract_balance + channel1.our_state.contract_balance

    our_balance0 = channel.get_balance(channel0.our_state, channel0.partner_state)
    partner_balance0 = channel.get_balance(channel0.partner_state, channel0.our_state)
    assert our_balance0 + partner_balance0 == total_token

    our_balance1 = channel.get_balance(channel1.our_state, channel1.partner_state)
    partner_balance1 = channel.get_balance(channel1.partner_state, channel1.our_state)
    assert our_balance1 + partner_balance1 == total_token

    locked_amount0 = sum(lock.amount for lock in pending_locks0)
    locked_amount1 = sum(lock.amount for lock in pending_locks1)

    assert_balance(channel0, balance0, locked_amount0)
    assert_balance(channel1, balance1, locked_amount1)

    # a participant's outstanding is the other's pending locks.
    assert_locked(channel0, pending_locks0)
    assert_locked(channel1, pending_locks1)

    assert_mirror(channel0, channel1)
    assert_mirror(channel1, channel0)


def wait_assert(func: Callable, *args, **kwargs) -> None:
    """ Utility to re-run `func` if it raises an assert. Return once `func`
    doesn't hit a failed assert anymore.

    This will loop forever unless a gevent.Timeout is used.
    """
    while True:
        try:
            func(*args, **kwargs)
        except AssertionError as e:
            try:
                gevent.sleep(0.5)
            except gevent.Timeout:
                raise e
        else:
            break


def assert_mirror(original: NettingChannelState, mirror: NettingChannelState) -> None:
    """ Assert that `mirror` has a correct `partner_state` to represent `original`."""
    original_locked_amount = channel.get_amount_locked(original.our_state)
    mirror_locked_amount = channel.get_amount_locked(mirror.partner_state)
    assert original_locked_amount == mirror_locked_amount

    balance0 = channel.get_balance(original.our_state, original.partner_state)
    balance1 = channel.get_balance(mirror.partner_state, mirror.our_state)
    assert balance0 == balance1

    balanceproof0 = channel.get_current_balanceproof(original.our_state)
    balanceproof1 = channel.get_current_balanceproof(mirror.partner_state)
    assert balanceproof0 == balanceproof1

    distributable0 = channel.get_distributable(original.our_state, original.partner_state)
    distributable1 = channel.get_distributable(mirror.partner_state, mirror.our_state)
    assert distributable0 == distributable1


def assert_locked(
        from_channel: NettingChannelState,
        pending_locks: List[HashTimeLockState],
) -> None:
    """ Assert the locks created from `from_channel`. """
    # a locked transfer is registered in the _partner_ state
    if pending_locks:
        leaves = [sha3(lock.encoded) for lock in pending_locks]
        layers = compute_layers(leaves)
        tree = MerkleTreeState(layers)
    else:
        tree = make_empty_merkle_tree()

    assert from_channel.our_state.merkletree == tree

    for lock in pending_locks:
        pending = lock.secrethash in from_channel.our_state.secrethashes_to_lockedlocks
        unclaimed = lock.secrethash in from_channel.our_state.secrethashes_to_unlockedlocks
        assert pending or unclaimed


def assert_balance(
        from_channel: NettingChannelState,
        balance: Balance,
        locked: LockedAmount,
) -> None:
    """ Assert the from_channel overall token values. """
    assert balance >= 0
    assert locked >= 0

    distributable = balance - locked
    channel_distributable = channel.get_distributable(
        from_channel.our_state,
        from_channel.partner_state,
    )
    channel_balance = channel.get_balance(from_channel.our_state, from_channel.partner_state)
    channel_locked_amount = channel.get_amount_locked(from_channel.our_state)

    msg = f'channel balance does not match. Expected: {balance} got: {channel_balance}'
    assert channel_balance == balance, msg

    msg = (
        f'channel distributable amount does not match. '
        f'Expected: {distributable} got: {channel_distributable}'
    )
    assert channel_distributable == distributable, msg

    msg = f'channel locked amount does not match. Expected: {locked} got: {channel_locked_amount}'
    assert channel_locked_amount == locked, msg

    msg = (
        f'locked_amount ({locked}) + distributable ({distributable}) '
        f'did not equal the balance ({balance})'
    )
    assert balance == locked + distributable, msg


def make_mediated_transfer(
        from_channel: NettingChannelState,
        partner_channel: NettingChannelState,
        initiator: InitiatorAddress,
        target: TargetAddress,
        lock: HashTimeLockState,
        pkey: bytes,
        secret: Optional[Secret] = None,
) -> LockedTransfer:
    """ Helper to create and register a mediated transfer from `from_channel` to
    `partner_channel`."""
    payment_identifier = channel.get_next_nonce(from_channel.our_state)
    message_identifier = random.randint(0, UINT64_MAX)

    lockedtransfer = channel.send_lockedtransfer(
        from_channel,
        initiator,
        target,
        lock.amount,
        message_identifier,
        payment_identifier,
        lock.expiration,
        lock.secrethash,
    )
    mediated_transfer_msg = LockedTransfer.from_event(lockedtransfer)

    mediated_transfer_msg.sign(LocalSigner(pkey))

    # compute the signature
    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)
    lockedtransfer.balance_proof = balance_proof

    # if this fails it's not the right key for the current `from_channel`
    assert mediated_transfer_msg.sender == from_channel.our_state.address
    receive_lockedtransfer = lockedtransfersigned_from_message(mediated_transfer_msg)

    channel.handle_receive_lockedtransfer(
        partner_channel,
        receive_lockedtransfer,
    )

    if secret is not None:
        secrethash = sha3(secret)

        channel.register_offchain_secret(from_channel, secret, secrethash)
        channel.register_offchain_secret(partner_channel, secret, secrethash)

    return mediated_transfer_msg


def make_receive_transfer_mediated(
        channel_state: NettingChannelState,
        privkey: bytes,
        nonce: Nonce,
        transferred_amount: TokenAmount,
        lock: HashTimeLockState,
        merkletree_leaves: List[Keccak256] = None,
        locked_amount: Optional[LockedAmount] = None,
        chain_id: Optional[ChainID] = None,
) -> LockedTransferSignedState:

    if not isinstance(lock, HashTimeLockState):
        raise ValueError('lock must be of type HashTimeLockState')

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    if merkletree_leaves is None:
        layers = [[lock.lockhash]]
    else:
        assert lock.lockhash in merkletree_leaves
        layers = compute_layers(merkletree_leaves)

    if locked_amount is None:
        locked_amount = lock.amount

    assert locked_amount >= lock.amount

    locksroot = layers[MERKLEROOT][0]

    payment_identifier = nonce
    transfer_target = make_address()
    transfer_initiator = make_address()
    chain_id = chain_id or channel_state.chain_id
    mediated_transfer_msg = LockedTransfer(
        chain_id=chain_id,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=payment_identifier,
        nonce=nonce,
        token_network_address=channel_state.token_network_identifier,
        token=channel_state.token_address,
        channel_identifier=channel_state.identifier,
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        recipient=channel_state.partner_state.address,
        locksroot=locksroot,
        lock=lock,
        target=transfer_target,
        initiator=transfer_initiator,
    )
    mediated_transfer_msg.sign(signer)

    balance_proof = balanceproof_from_envelope(mediated_transfer_msg)

    receive_lockedtransfer = LockedTransferSignedState(
        random.randint(0, UINT64_MAX),
        payment_identifier,
        channel_state.token_address,
        balance_proof,
        lock,
        transfer_initiator,
        transfer_target,
    )

    return receive_lockedtransfer


def make_receive_expired_lock(
        channel_state: NettingChannelState,
        privkey: bytes,
        nonce: Nonce,
        transferred_amount: TokenAmount,
        lock: HashTimeLockState,
        merkletree_leaves: List[Keccak256] = None,
        locked_amount: LockedAmount = None,
        chain_id: ChainID = None,
) -> ReceiveLockExpired:

    if not isinstance(lock, HashTimeLockState):
        raise ValueError('lock must be of type HashTimeLockState')

    signer = LocalSigner(privkey)
    address = signer.address
    if address not in (channel_state.our_state.address, channel_state.partner_state.address):
        raise ValueError('Private key does not match any of the participants.')

    if merkletree_leaves is None:
        layers = make_empty_merkle_tree().layers
    else:
        assert lock.lockhash not in merkletree_leaves
        layers = compute_layers(merkletree_leaves)

    locksroot = layers[MERKLEROOT][0]

    chain_id = chain_id or channel_state.chain_id
    lock_expired_msg = LockExpired(
        chain_id=chain_id,
        nonce=nonce,
        message_identifier=random.randint(0, UINT64_MAX),
        transferred_amount=transferred_amount,
        locked_amount=locked_amount,
        locksroot=locksroot,
        channel_identifier=channel_state.identifier,
        token_network_address=channel_state.token_network_identifier,
        recipient=channel_state.partner_state.address,
        secrethash=lock.secrethash,
    )
    lock_expired_msg.sign(signer)

    balance_proof = balanceproof_from_envelope(lock_expired_msg)

    receive_lockedtransfer = ReceiveLockExpired(
        balance_proof=balance_proof,
        secrethash=lock.secrethash,
        message_identifier=random.randint(0, UINT64_MAX),
    )

    return receive_lockedtransfer
