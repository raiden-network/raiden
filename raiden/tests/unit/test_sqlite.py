import itertools
import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from raiden.messages import Lock
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SerializedSQLiteStorage, SQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.mediated_transfer.events import (
    SendBalanceProof,
    SendLockedTransfer,
    SendLockExpired,
    SendRefundTransfer,
)
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitMediator,
    ActionInitTarget,
    ReceiveLockExpired,
    ReceiveTransferRefund,
    ReceiveTransferRefundCancelRoute,
)
from raiden.transfer.state import BalanceProofUnsignedState
from raiden.transfer.state_change import ReceiveUnlock
from raiden.transfer.utils import (
    get_event_with_balance_proof_by_balance_hash,
    get_state_change_with_balance_proof_by_balance_hash,
)
from raiden.utils import sha3


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


def make_balance_proof_from_counter(counter) -> BalanceProofUnsignedState:
    return BalanceProofUnsignedState(
        nonce=next(counter),
        transferred_amount=next(counter),
        locked_amount=next(counter),
        locksroot=sha3(next(counter).to_bytes(1, 'big')),
        canonical_identifier=factories.make_canonical_identifier(
            chain_identifier=next(counter),
            token_network_address=factories.make_address(),
            channel_identifier=next(counter),
        ),
    )


def make_transfer_from_counter(counter):
    return factories.make_transfer(
        amount=next(counter),
        initiator=factories.make_address(),
        target=factories.make_address(),
        expiration=next(counter),
        secret=factories.make_secret(next(counter)),
    )


def make_signed_transfer_from_counter(counter):
    lock = Lock(
        amount=next(counter),
        expiration=next(counter),
        secrethash=sha3(factories.make_secret(next(counter))),
    )

    signed_transfer = factories.make_signed_transfer_state(
        amount=next(counter),
        initiator=factories.make_address(),
        target=factories.make_address(),
        expiration=next(counter),
        secret=factories.make_secret(next(counter)),
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
        from_channel,
        factories.LockedTransferSignedStateProperties(
            transfer=factories.LockedTransferProperties(
                balance_proof=factories.BalanceProofProperties(
                    transferred_amount=0,
                    token_network_identifier=from_channel.token_network_identifier,
                ),
                amount=1,
                expiration=expiration,
                secret=sha3(factories.make_secret(next(counter))),
                initiator=factories.make_address(),
                target=factories.make_address(),
                payment_identifier=next(counter),
            ),
            sender=factories.HOP1,
            pkey=factories.HOP1_KEY,
        ),
    )
    return from_route, from_transfer


def test_get_state_change_with_balance_proof():
    """ All state changes which contain a balance proof must be found by when
    querying the database.
    """
    serializer = JSONSerializer
    storage = SerializedSQLiteStorage(':memory:', serializer)
    counter = itertools.count()

    lock_expired = ReceiveLockExpired(
        balance_proof=make_signed_balance_proof_from_counter(counter),
        secrethash=sha3(factories.make_secret(next(counter))),
        message_identifier=next(counter),
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

    statechanges_balanceproofs = [
        (lock_expired, lock_expired.balance_proof),
        (unlock, unlock.balance_proof),
        (transfer_refund, transfer_refund.transfer.balance_proof),
        (transfer_refund_cancel_route, transfer_refund_cancel_route.transfer.balance_proof),
        (action_init_mediator, action_init_mediator.from_transfer.balance_proof),
        (action_init_target, action_init_target.transfer.balance_proof),
    ]

    timestamp = datetime.utcnow().isoformat(timespec='milliseconds')

    for state_change, _ in statechanges_balanceproofs:
        storage.write_state_change(state_change, timestamp)

    # Make sure state changes are returned in the correct order in which they were stored
    stored_statechanges = storage.get_statechanges_by_identifier(1, 'latest')
    assert isinstance(stored_statechanges[0], ReceiveLockExpired)
    assert isinstance(stored_statechanges[1], ReceiveUnlock)
    assert isinstance(stored_statechanges[2], ReceiveTransferRefund)
    assert isinstance(stored_statechanges[3], ReceiveTransferRefundCancelRoute)
    assert isinstance(stored_statechanges[4], ActionInitMediator)
    assert isinstance(stored_statechanges[5], ActionInitTarget)

    # Make sure state changes are returned in the correct order in which they were stored
    stored_statechanges = storage.get_statechanges_by_identifier(1, 2)
    assert isinstance(stored_statechanges[0], ReceiveLockExpired)
    assert isinstance(stored_statechanges[1], ReceiveUnlock)

    for state_change, balance_proof in statechanges_balanceproofs:
        state_change_record = get_state_change_with_balance_proof_by_balance_hash(
            storage=storage,
            canonical_identifier=balance_proof.canonical_identifier,
            sender=balance_proof.sender,
            balance_hash=balance_proof.balance_hash,
        )
        assert state_change_record.data == state_change


def test_get_event_with_balance_proof():
    """ All events which contain a balance proof must be found by when
    querying the database.
    """
    serializer = JSONSerializer
    storage = SerializedSQLiteStorage(':memory:', serializer)
    counter = itertools.count()

    lock_expired = SendLockExpired(
        recipient=factories.make_address(),
        message_identifier=next(counter),
        balance_proof=make_balance_proof_from_counter(counter),
        secrethash=sha3(factories.make_secret(next(counter))),
    )
    locked_transfer = SendLockedTransfer(
        recipient=factories.make_address(),
        channel_identifier=factories.make_channel_identifier(),
        message_identifier=next(counter),
        transfer=make_transfer_from_counter(counter),
    )
    balance_proof = SendBalanceProof(
        recipient=factories.make_address(),
        channel_identifier=factories.make_channel_identifier(),
        message_identifier=next(counter),
        payment_identifier=next(counter),
        token_address=factories.make_address(),
        secret=factories.make_secret(next(counter)),
        balance_proof=make_balance_proof_from_counter(counter),
    )
    refund_transfer = SendRefundTransfer(
        recipient=factories.make_address(),
        channel_identifier=factories.make_channel_identifier(),
        message_identifier=next(counter),
        transfer=make_transfer_from_counter(counter),
    )

    events_balanceproofs = [
        (lock_expired, lock_expired.balance_proof),
        (locked_transfer, locked_transfer.balance_proof),
        (balance_proof, balance_proof.balance_proof),
        (refund_transfer, refund_transfer.transfer.balance_proof),
    ]

    timestamp = datetime.utcnow().isoformat(timespec='milliseconds')
    state_change = ''
    for event, _ in events_balanceproofs:
        state_change_identifier = storage.write_state_change(
            state_change,
            timestamp,
        )
        storage.write_events(
            state_change_identifier=state_change_identifier,
            events=[event],
            log_time=timestamp,
        )

    for event, balance_proof in events_balanceproofs:
        event_record = get_event_with_balance_proof_by_balance_hash(
            storage=storage,
            canonical_identifier=balance_proof.canonical_identifier,
            balance_hash=balance_proof.balance_hash,
        )
        assert event_record.data == event
        # Checking that balance proof attribute can be accessed for all events.
        # Issue https://github.com/raiden-network/raiden/issues/3179
        assert event_record.data.balance_proof == event.balance_proof


def test_log_run():
    with patch('raiden.storage.sqlite.get_system_spec') as get_speck_mock:
        get_speck_mock.return_value = dict(raiden='1.2.3')
        store = SerializedSQLiteStorage(':memory:', None)
        store.log_run()
    cursor = store.conn.cursor()
    cursor.execute('SELECT started_at, raiden_version FROM runs')
    run = cursor.fetchone()
    now = datetime.utcnow()
    assert now - timedelta(seconds=2) <= run[0] <= now, f'{run[0]} not right before {now}'
    assert run[1] == '1.2.3'


def test_batch_query_state_changes():
    storage = SQLiteStorage(':memory:')
    # Add the v18 state changes to the DB
    state_changes_file = Path(__file__).parent / 'storage/migrations/data/v18_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
        )

    # Test that querying the state changes in batches of 10 works
    state_changes_num = 87
    state_changes = []
    for state_changes_batch in storage.batch_query_state_changes(batch_size=10):
        state_changes.extend(state_changes_batch)

    assert len(state_changes) == state_changes_num
    for i in range(1, 87):
        assert state_changes[i - 1].state_change_identifier == i

    # Test that we can also add a filter
    state_changes = []
    state_changes_batch_query = storage.batch_query_state_changes(
        batch_size=10,
        filters=[('_type', 'raiden.transfer.state_change.Block')],
    )
    for state_changes_batch in state_changes_batch_query:
        state_changes.extend(state_changes_batch)
    assert len(state_changes) == 77

    # Test that filter works with logical or and a wildmark too
    state_changes = []
    state_changes_batch_query = storage.batch_query_state_changes(
        batch_size=10,
        filters=[
            # Should be 5 of them
            ('_type', 'raiden.transfer.state_change.ContractReceiveChannel%'),
            # Should be only 1
            ('_type', 'raiden.transfer.state_change.ContractReceiveNewPaymentNetwork'),
        ],
        logical_and=False,
    )
    for state_changes_batch in state_changes_batch_query:
        state_changes.extend(state_changes_batch)
    assert len(state_changes) == 6


def test_batch_query_event_records():
    storage = SQLiteStorage(':memory:')
    # Add the v18 state changes to the DB (need them to satisfy foreign key constraints)
    state_changes_file = Path(__file__).parent / 'storage/migrations/data/v18_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
        )

    # Add the v18 events to the DB
    events_file = Path(__file__).parent / 'storage/migrations/data/v18_events.json'
    events_data = json.loads(events_file.read_text())
    for event in events_data:
        state_change_identifier = event[1]
        event_data = json.dumps(event[2])
        log_time = datetime.utcnow().isoformat(timespec='milliseconds')
        event_tuple = (
            None,
            state_change_identifier,
            log_time,
            event_data,
        )
        storage.write_events([event_tuple])

    # Test that querying the events in batches of 1 works
    events = []
    for events_batch in storage.batch_query_event_records(batch_size=1):
        events.extend(events_batch)
    assert len(events) == 3

    # Test that we can also add a filter
    events = []
    events_batch_query = storage.batch_query_event_records(
        batch_size=1,
        filters=[('_type', 'raiden.transfer.events.EventPaymentReceivedSuccess')],
    )
    for events_batch in events_batch_query:
        events.extend(events_batch)
    assert len(events) == 1
    event_type = json.loads(events[0].data)['_type']
    assert event_type == 'raiden.transfer.events.EventPaymentReceivedSuccess'

    # Test that we can also add a filter with logical OR
    events = []
    events_batch_query = storage.batch_query_event_records(
        batch_size=1,
        filters=[
            ('_type', 'raiden.transfer.events.EventPaymentReceivedSuccess'),
            ('_type', 'raiden.transfer.events.ContractSendChannelSettle'),
        ],
        logical_and=False,
    )
    for events_batch in events_batch_query:
        events.extend(events_batch)
    assert len(events) == 2
