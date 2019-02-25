import json
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils.migrations import create_fake_web3_for_block_hash
from raiden.utils.upgrades import UpgradeManager


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path))

    state_changes_file = Path(__file__).parent / 'data/v18_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())

    for state_change_record in state_changes_data:
        storage.write_state_change(
            state_change=json.dumps(state_change_record[1]),
            log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
        )

    return storage


def test_upgrade_v18_to_v19(tmp_path):
    db_path = tmp_path / Path('test.db')

    old_db_filename = tmp_path / Path('v18_log.db')
    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
        storage = setup_storage(str(old_db_filename))
        with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=18):
            storage.update_version()
        storage.conn.close()

    web3, block_to_blockhash = create_fake_web3_for_block_hash(number_of_blocks=100)
    manager = UpgradeManager(db_filename=str(db_path), web3=web3)
    manager.run()

    storage = SQLiteStorage(str(db_path))
    state_change_records = storage.get_all_state_changes()
    for state_change_record in state_change_records:
        data = json.loads(state_change_record.data)
        affected_state_change = (
            'raiden.transfer.state_change.ContractReceive' in data['_type'] or
            'raiden.transfer.state_change.ActionInitChain' in data['_type']
        )
        if affected_state_change:
            assert 'block_hash' in data
            block_number = int(data['block_number'])
            assert block_to_blockhash[block_number].hex() == data['block_hash']
