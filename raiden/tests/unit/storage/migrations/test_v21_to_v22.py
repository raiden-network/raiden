import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from eth_utils import to_canonical_address

from raiden.storage import serialize
from raiden.storage.migrations.v21_to_v22 import (
    SOURCE_VERSION,
    TARGET_VERSION,
    check_constraint,
    constraint_has_canonical_identifier_or_values_removed,
    upgrade_v21_to_v22,
    yield_objects,
)
from raiden.storage.sqlite import SerializedSQLiteStorage, SQLiteStorage
from raiden.tests.utils.mocks import MockRaidenService
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def setup_storage_dev(db_path, prefix):
    storage = SQLiteStorage(str(db_path))

    base_dir, prefix = os.path.split(prefix)
    matching_files = [fn for fn in os.listdir(base_dir) if fn.startswith(prefix)]

    state_changes_filename = [fn for fn in matching_files if 'state_changes-0x' in fn][0]
    state_changes_file = Path(base_dir) / Path(state_changes_filename)
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
        )

    events_filename = [fn for fn in matching_files if 'events-0x' in fn][0]
    events_file = Path(base_dir) / Path(events_filename)
    events_data = json.loads(events_file.read_text())
    event_tuples = []
    for event in events_data:
        state_change_identifier = event[1]
        event_data = json.dumps(event[2])
        log_time = datetime.utcnow().isoformat(timespec='milliseconds')
        event_tuples.append((
            None,
            state_change_identifier,
            log_time,
            event_data,
        ))
    storage.write_events(event_tuples)

    snapshots_filename = [fn for fn in matching_files if 'snapshots-0x' in fn][0]
    chain_state_data = Path(base_dir) / Path(snapshots_filename)
    chain_state = chain_state_data.read_text()
    snapshots = json.loads(chain_state)
    for identifier, statechange_id, data in zip(
            *[snapshots[i::3] for i in range(3)],
    ):
        cursor = storage.conn.cursor()
        cursor.execute(
            """
            INSERT INTO state_snapshot(identifier, statechange_id, data)
            VALUES(?, ?, ?)
            """, (identifier, statechange_id, json.dumps(data)),
        )
    storage.conn.commit()
    storage.conn.close()
    storage = SerializedSQLiteStorage(str(db_path), serialize.JSONSerializer())
    address = snapshots_filename.rsplit('-')[-1].split('.')[0]
    return storage, address


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path))

    state_changes_file = Path(__file__).parent / f'data/v{SOURCE_VERSION}_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
        )

    events_file = Path(__file__).parent / f'data/v{SOURCE_VERSION}_events.json'
    events_data = json.loads(events_file.read_text())
    event_tuples = []
    for event in events_data:
        state_change_identifier = event[1]
        event_data = json.dumps(event[2])
        log_time = datetime.utcnow().isoformat(timespec='milliseconds')
        event_tuples.append((
            None,
            state_change_identifier,
            log_time,
            event_data,
        ))
    storage.write_events(event_tuples)

    chain_state_data = Path(__file__).parent / f'data/v{SOURCE_VERSION}_chainstate.json'
    chain_state = chain_state_data.read_text()
    cursor = storage.conn.cursor()
    cursor.execute(
        """
        INSERT INTO state_snapshot(identifier, statechange_id, data)
        VALUES(1, 1, ?)
        """, (chain_state,),
    )
    storage.conn.commit()
    storage.conn.close()
    storage = SerializedSQLiteStorage(str(db_path), serialize.JSONSerializer())
    return storage


def test_upgrade_v21_to_v22(tmp_path):
    for prefix in (
            set(n.rsplit('-', 2)[0] for n in os.listdir('/tmp/dings/'))
    ):
        with patch('raiden.utils.upgrades.latest_db_file') as latest_db_file:
            old_db_filename = tmp_path / Path(f'v{SOURCE_VERSION}_log.db')
            latest_db_file.return_value = str(old_db_filename)
            print(f'prefix {prefix}')
            storage, address = setup_storage_dev(str(old_db_filename), '/tmp/dings/' + prefix)
            with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=SOURCE_VERSION):
                storage.update_version()
            storage.conn.close()

            raiden_service_mock = MockRaidenService()
            raiden_service_mock.address = to_canonical_address(address)

            db_path = tmp_path / Path(f'v{TARGET_VERSION}_log.db')
            manager = UpgradeManager(db_filename=str(db_path), raiden=raiden_service_mock)
            with patch(
                    'raiden.utils.upgrades.UPGRADES_LIST',
                    new=[UpgradeRecord(from_version=SOURCE_VERSION, function=upgrade_v21_to_v22)],
            ):
                manager.run()

            storage = SerializedSQLiteStorage(str(db_path), serialize.JSONSerializer())
            for batch in storage.batch_query_event_records(batch_size=500):
                for event in batch:
                    for obj in yield_objects(event.data):
                        check_constraint(
                            obj,
                            constraint=constraint_has_canonical_identifier_or_values_removed,
                        )
            for batch in storage.batch_query_state_changes(batch_size=500):
                for state_change in batch:
                    for obj in yield_objects(state_change.data):
                        check_constraint(
                            obj,
                            constraint=constraint_has_canonical_identifier_or_values_removed,
                        )
            for snapshot in storage.get_snapshots():
                for obj in yield_objects(snapshot.data):
                    check_constraint(
                        obj,
                        constraint=constraint_has_canonical_identifier_or_values_removed,
                    )

            assert os.path.isfile(str(db_path))
            assert os.path.isfile(str(old_db_filename))
            os.unlink(str(db_path))
            os.unlink(str(old_db_filename))
            assert not os.path.exists(str(db_path))
            assert not os.path.exists(str(old_db_filename))

    # now run some tests after the upgrade
    # import pdb
    # pdb.set_trace()
