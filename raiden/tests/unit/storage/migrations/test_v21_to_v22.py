import json
import os
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from eth_utils import to_canonical_address

from raiden.storage.migrations.v21_to_v22 import (
    SOURCE_VERSION,
    TARGET_VERSION,
    constraint_has_canonical_identifier_or_values_removed,
    upgrade_v21_to_v22,
    walk_dicts,
)
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils.mocks import MockRaidenService
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path))

    state_changes_file = Path(__file__).parent / f"data/v{SOURCE_VERSION}_statechanges.json"
    state_changes_data = json.loads(state_changes_file.read_text())
    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec="milliseconds"),
        )

    events_file = Path(__file__).parent / f"data/v{SOURCE_VERSION}_events.json"
    events_data = json.loads(events_file.read_text())
    event_tuples = []
    for event in events_data:
        state_change_identifier = event[1]
        event_data = json.dumps(event[2])
        log_time = datetime.utcnow().isoformat(timespec="milliseconds")
        event_tuples.append((None, state_change_identifier, log_time, event_data))
    storage.write_events(event_tuples)

    chain_state_data = Path(__file__).parent / f"data/v{SOURCE_VERSION}_chainstate.json"
    chain_state = chain_state_data.read_text()
    snapshots = json.loads(chain_state)
    for identifier, statechange_id, data in zip(*[snapshots[i::3] for i in range(3)]):
        cursor = storage.conn.cursor()
        cursor.execute(
            """
            INSERT INTO state_snapshot(identifier, statechange_id, data)
            VALUES(?, ?, ?)
            """,
            (identifier, statechange_id, json.dumps(data)),
        )
    storage.conn.commit()
    storage.conn.close()
    storage = SQLiteStorage(str(db_path))
    return storage


def test_upgrade_v21_to_v22(tmp_path):
    address = to_canonical_address("0x87A749D9b9c0c91AC009AeeBd74313D1a736A24C")
    with patch("raiden.utils.upgrades.latest_db_file") as latest_db_file:
        old_db_filename = tmp_path / Path(f"v{SOURCE_VERSION}_log.db")
        latest_db_file.return_value = str(old_db_filename)
        storage = setup_storage(str(old_db_filename))
        with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=SOURCE_VERSION):
            storage.update_version()
        storage.conn.close()

        raiden_service_mock = MockRaidenService()
        raiden_service_mock.address = address

        db_path = tmp_path / Path(f"v{TARGET_VERSION}_log.db")
        manager = UpgradeManager(db_filename=str(db_path), raiden=raiden_service_mock)
        with patch(
            "raiden.utils.upgrades.UPGRADES_LIST",
            new=[UpgradeRecord(from_version=SOURCE_VERSION, function=upgrade_v21_to_v22)],
        ):
            manager.run()

        storage = SQLiteStorage(str(db_path))
        for batch in storage.batch_query_event_records(batch_size=500):
            for event in batch:
                walk_dicts(event, constraint_has_canonical_identifier_or_values_removed)
        for batch in storage.batch_query_state_changes(batch_size=500):
            for state_change in batch:
                walk_dicts(state_change, constraint_has_canonical_identifier_or_values_removed)
        for snapshot in storage.get_snapshots():
            walk_dicts(snapshot, constraint_has_canonical_identifier_or_values_removed)

        assert os.path.isfile(str(db_path))
        assert os.path.isfile(str(old_db_filename))
        os.unlink(str(db_path))
        os.unlink(str(old_db_filename))
        assert not os.path.exists(str(db_path))
        assert not os.path.exists(str(old_db_filename))
