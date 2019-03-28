import json

from gevent.pool import Pool
from web3 import Web3

from raiden.exceptions import InvalidDBData
from raiden.storage.sqlite import SQLiteStorage
from raiden.utils.typing import Any, BlockNumber, Dict, NamedTuple, Tuple

SOURCE_VERSION = 18
TARGET_VERSION = 19


class BlockHashCache():
    """A small cache for blocknumber to blockhashes to optimize this migration a bit

    This cache lives only during the v18->v19 migration where numerous RPC calls are
    expected to be made, many of them probably querying the same block_number -> block_hash.
    To save RPC calls and make it a bit faster we keep this short-lived cache for the duration
    of the migration
    """

    def __init__(self, web3: Web3):
        self.web3 = web3
        self.mapping = {}

    def get(self, block_number: BlockNumber) -> str:
        """Given a block number returns the hex representation of the blockhash"""
        if block_number in self.mapping:
            return self.mapping[block_number]

        block_hash = self.web3.eth.getBlock(block_number)['hash']
        block_hash = block_hash.hex()
        self.mapping[block_number] = block_hash
        return block_hash


class BlockQueryAndUpdateRecord(NamedTuple):
    block_number: BlockNumber
    data: Dict[str, Any]
    state_change_identifier: int
    cache: BlockHashCache


def _query_blocknumber_and_update_statechange_data(
        record: BlockQueryAndUpdateRecord,
) -> Tuple[str, int]:
    data = record.data
    data['block_hash'] = record.cache.get(record.block_number)
    return (json.dumps(data), record.state_change_identifier)


def _add_blockhash_to_state_changes(storage: SQLiteStorage, cache: BlockHashCache) -> None:
    """Adds blockhash to ContractReceiveXXX and ActionInitChain state changes"""

    batch_size = 50
    batch_query = storage.batch_query_state_changes(
        batch_size=batch_size,
        filters=[
            ('_type', 'raiden.transfer.state_change.ContractReceive%'),
            ('_type', 'raiden.transfer.state_change.ActionInitChain'),
        ],
        logical_and=False,
    )
    for state_changes_batch in batch_query:
        # Gather query records to pass to gevent pool imap to have concurrent RPC calls
        query_records = []
        for state_change in state_changes_batch:
            data = json.loads(state_change.data)
            assert 'block_hash' not in data, 'v18 state changes cant contain blockhash'
            record = BlockQueryAndUpdateRecord(
                block_number=int(data['block_number']),
                data=data,
                state_change_identifier=state_change.state_change_identifier,
                cache=cache,
            )
            query_records.append(record)

        # Now perform the queries in parallel with gevent.Pool.imap and gather the
        # updated tuple entries that will update the DB
        updated_state_changes = []
        pool_generator = Pool(batch_size).imap(
            _query_blocknumber_and_update_statechange_data,
            query_records,
        )
        for entry in pool_generator:
            updated_state_changes.append(entry)

        # Finally update the DB with a batched executemany()
        storage.update_state_changes(updated_state_changes)


def _add_blockhash_to_events(storage: SQLiteStorage, cache: BlockHashCache) -> None:
    """Adds blockhash to all ContractSendXXX events"""
    batch_query = storage.batch_query_event_records(
        batch_size=500,
        filters=[('_type', 'raiden.transfer.events.ContractSend%')],
    )
    for events_batch in batch_query:
        updated_events = []
        for event in events_batch:
            data = json.loads(event.data)
            assert 'triggered_by_block_hash' not in data, 'v18 events cant contain blockhash'
            # Get the state_change that triggered the event and get its hash
            matched_state_changes = storage.get_statechanges_by_identifier(
                from_identifier=event.state_change_identifier,
                to_identifier=event.state_change_identifier,
            )
            result_length = len(matched_state_changes)
            msg = 'multiple state changes should not exist for the same identifier'
            assert result_length == 1, msg

            statechange_data = json.loads(matched_state_changes[0])
            if 'block_hash' in statechange_data:
                data['triggered_by_block_hash'] = statechange_data['block_hash']
            elif 'block_number' in statechange_data:
                block_number = int(statechange_data['block_number'])
                data['triggered_by_block_hash'] = cache.get(block_number)

            updated_events.append((
                json.dumps(data),
                event.event_identifier,
            ))

        storage.update_events(updated_events)


def _transform_snapshot(
        raw_snapshot: str,
        storage: SQLiteStorage,
        cache: BlockHashCache,
) -> str:
    """Upgrades a single snapshot by adding the blockhash to it and to any pending transactions"""
    snapshot = json.loads(raw_snapshot)
    block_number = int(snapshot['block_number'])
    snapshot['block_hash'] = cache.get(block_number)

    pending_transactions = snapshot['pending_transactions']
    new_pending_transactions = []
    for transaction_data in pending_transactions:
        if 'raiden.transfer.events.ContractSend' not in transaction_data['_type']:
            raise InvalidDBData(
                "Error during v18 -> v19 upgrade. Chain state's pending transactions "
                "should only contain ContractSend transactions",
            )

        # For each pending transaction find the corresponding DB event record.
        event_record = storage.get_latest_event_by_data_field(
            filters=transaction_data,
        )
        if not event_record.data:
            raise InvalidDBData(
                'Error during v18 -> v19 upgrade. Could not find a database event '
                'table entry for a pending transaction.',
            )

        event_record_data = json.loads(event_record.data)
        transaction_data['triggered_by_block_hash'] = event_record_data['triggered_by_block_hash']
        new_pending_transactions.append(transaction_data)

    snapshot['pending_transactions'] = new_pending_transactions
    return json.dumps(snapshot)


class TransformSnapshotRecord(NamedTuple):
    data: Any
    identifier: int
    storage: SQLiteStorage
    cache: BlockHashCache


def _do_transform_snapshot(record: TransformSnapshotRecord) -> Tuple[Dict[str, Any], int]:
    new_snapshot = _transform_snapshot(
        raw_snapshot=record.data,
        storage=record.storage,
        cache=record.cache,
    )
    return new_snapshot, record.identifier


def _transform_snapshots_for_blockhash(storage: SQLiteStorage, cache: BlockHashCache) -> None:
    """Upgrades the snapshots by adding the blockhash to it and to any pending transactions"""

    snapshots = storage.get_snapshots()
    snapshot_records = [
        TransformSnapshotRecord(
            data=snapshot.data,
            identifier=snapshot.identifier,
            storage=storage,
            cache=cache,
        )
        for snapshot in snapshots
    ]

    pool_generator = Pool(len(snapshots)).imap(_do_transform_snapshot, snapshot_records)

    updated_snapshots_data = []
    for result in pool_generator:
        updated_snapshots_data.append(result)

    storage.update_snapshots(updated_snapshots_data)


def upgrade_v18_to_v19(
        storage: SQLiteStorage,
        old_version: int,
        current_version: int,  # pylint: disable=unused-argument
        web3: Web3,
        **kwargs,  # pylint: disable=unused-argument
) -> int:
    if old_version == SOURCE_VERSION:
        cache = BlockHashCache(web3)
        _add_blockhash_to_state_changes(storage, cache)
        _add_blockhash_to_events(storage, cache)
        # The snapshot transformation should come last because the update of the
        # transaction queue of the chain state relies on the events having been updated
        _transform_snapshots_for_blockhash(storage, cache)

    return TARGET_VERSION
