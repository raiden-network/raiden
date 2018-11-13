import itertools
from datetime import datetime

from eth_utils import to_checksum_address

from raiden.messages import Lock
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.state_change import ReceiveTransferDirect, ReceiveUnlock
from raiden.utils import sha3
from raiden.utils.serialization import serialize_bytes


def make_signed_balance_proof_from_counter(counter):
    lock = Lock(
        amount=next(counter),
        expiration=next(counter),
        secrethash=sha3(factories.make_secret(next(counter))),
    )
    lock_expired_balance_proof = factories.make_signed_balance_proof(
        nonce=next(counter),
        transferred_amount=next(counter),
        locked_amount=next(counter),
        token_network_address=factories.make_address(),
        channel_identifier=next(counter),
        locksroot=sha3(lock.as_bytes),
        extra_hash=sha3(b''),
        private_key=factories.HOP1_KEY,
        sender_address=factories.HOP1,
    )

    return lock_expired_balance_proof


def make_signed_transfer_from_counter(counter):
    lock = Lock(
        amount=next(counter),
        expiration=next(counter),
        secrethash=sha3(factories.make_secret(next(counter))),
    )

    signed_transfer = factories.make_signed_transfer(
        amount=next(counter),
        initiator=factories.make_address(),
        target=factories.make_address(),
        expiration=next(counter),
        secret=sha3(factories.make_secret(next(counter))),
        payment_identifier=next(counter),
        message_identifier=next(counter),
        nonce=next(counter),
        transferred_amount=next(counter),
        locked_amount=next(counter),
        locksroot=sha3(lock.as_bytes),
        recipient=factories.make_address(),
        channel_identifier=next(counter),
        token_network_address=factories.make_address(),
        token=factories.make_address(),
        pkey=factories.HOP1_KEY,
        sender=factories.HOP1,
    )

    return signed_transfer


def make_from_route_from_counter(counter):
    from_channel = factories.make_channel(
        partner_balance=next(counter),
        partner_address=factories.HOP1,
        token_address=factories.make_address(),
        channel_identifier=next(counter),
    )
    from_route = factories.route_from_channel(from_channel)

    expiration = factories.UNIT_REVEAL_TIMEOUT + 1

    from_transfer = factories.make_signed_transfer_for(
        channel_state=from_channel,
        amount=1,
        initiator=factories.make_address(),
        target=factories.make_address(),
        expiration=expiration,
        secret=sha3(factories.make_secret(next(counter))),
        identifier=next(counter),
        nonce=1,
        transferred_amount=0,
        locked_amount=None,
        pkey=factories.HOP1_KEY,
        sender=factories.HOP1,
    )
    return from_route, from_transfer


def test_get_latest_state_change_by_data_field():
    """ All state changes which contain a balance proof must be found by when
    querying the database.
    """
    serializer = JSONSerializer
    storage = SQLiteStorage(':memory:', serializer)
    counter = itertools.count()

    lock_expired = ReceiveLockExpired(
        balance_proof=make_signed_balance_proof_from_counter(counter),
        secrethash=sha3(factories.make_secret(next(counter))),
        message_identifier=next(counter),
    )
    transfer_direct = ReceiveTransferDirect(
        token_network_identifier=factories.make_address(),
        message_identifier=next(counter),
        payment_identifier=next(counter),
        balance_proof=make_signed_balance_proof_from_counter(counter),
    )
    unlock = ReceiveUnlock(
        message_identifier=next(counter),
        secret=sha3(factories.make_secret(next(counter))),
        balance_proof=make_signed_balance_proof_from_counter(counter),
    )
    transfer_refund = ReceiveTransferRefund(
        transfer=make_signed_transfer_from_counter(counter),
        routes=list(),
    )
    transfer_refund_cancel_route = ReceiveTransferRefundCancelRoute(
        routes=list(),
        transfer=make_signed_transfer_from_counter(counter),
        secret=sha3(factories.make_secret(next(counter))),
    )
    mediator_from_route, mediator_signed_transfer = make_from_route_from_counter(counter)
    action_init_mediator = ActionInitMediator(
        routes=list(),
        from_route=mediator_from_route,
        from_transfer=mediator_signed_transfer,
    )
    target_from_route, target_signed_transfer = make_from_route_from_counter(counter)
    action_init_target = ActionInitTarget(
        route=target_from_route,
        transfer=target_signed_transfer,
    )

    statechange_balanceproof = [
        (lock_expired, lock_expired.balance_proof),
        (transfer_direct, transfer_direct.balance_proof),
        (unlock, unlock.balance_proof),
        (transfer_refund, transfer_refund.transfer.balance_proof),
        (transfer_refund_cancel_route, transfer_refund_cancel_route.transfer.balance_proof),
        (action_init_mediator, action_init_mediator.from_transfer.balance_proof),
        (action_init_target, action_init_target.transfer.balance_proof),
    ]

    timestamp = datetime.utcnow().isoformat(timespec='milliseconds')

    for state_change, _ in statechange_balanceproof:
        storage.write_state_change(state_change, timestamp)

    for state_change, balance_proof in statechange_balanceproof:
        result = storage.get_latest_state_change_by_data_field({
            'balance_proof.chain_id': balance_proof.chain_id,
            'balance_proof.token_network_identifier': to_checksum_address(
                balance_proof.token_network_identifier,
            ),
            'balance_proof.channel_identifier': balance_proof.channel_identifier,
            'balance_proof.sender': to_checksum_address(balance_proof.sender),
            'balance_proof.locksroot': serialize_bytes(balance_proof.locksroot),
        })
        assert result.data == state_change
