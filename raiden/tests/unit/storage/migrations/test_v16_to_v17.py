import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from raiden.storage.migrations.v16_to_v17 import upgrade_v16_to_v17
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils.migrations import create_fake_web3_for_block_hash
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def setup_storage(db_path):
    # For a raw ActionInitChain let's get the v18 one. It should be the same as v16
    state_changes_file = Path(__file__).parent / 'data/v18_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())
    action_init_chain_data = json.dumps(state_changes_data[0][1])
    storage = SQLiteStorage(str(db_path))
    storage.write_state_change(
        state_change=action_init_chain_data,
        log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
    )

    # Also add the v16 chainstate directly to the DB
    chain_state_data = Path(__file__).parent / 'data/v16_chainstate.json'
    chain_state = chain_state_data.read_text()
    cursor = storage.conn.cursor()
    cursor.execute(
        """
        INSERT INTO state_snapshot(identifier, statechange_id, data)
        VALUES(1, 1, ?)
        """, (chain_state,),
    )
    storage.conn.commit()
    return storage


def test_upgrade_v16_to_v17(tmp_path):
    old_db_filename = tmp_path / Path('v16_log.db')
    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
        storage = setup_storage(str(old_db_filename))
        with patch('raiden.constants.RAIDEN_DB_VERSION', new=16):
            storage.update_version()
        storage.conn.close()

    db_path = tmp_path / Path('v17_log.db')
    web3, _ = create_fake_web3_for_block_hash(number_of_blocks=100)
    manager = UpgradeManager(db_filename=str(db_path), web3=web3)
    with patch(
            'raiden.utils.upgrades.UPGRADES_LIST',
            new=[UpgradeRecord(from_version=16, function=upgrade_v16_to_v17)],
    ):
        manager.run()

    storage = SQLiteStorage(str(db_path))
    snapshot = storage.get_latest_state_snapshot()
    assert snapshot is not None
