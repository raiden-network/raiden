import random
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.state_change import ActionInitChain
from raiden.utils.upgrades import UpgradeManager


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path), JSONSerializer())
    storage.write_state_change(
        ActionInitChain(
            pseudo_random_generator=random.Random(),
            block_number=1,
            our_address=factories.make_address(),
            chain_id=1,
        ),
        datetime.utcnow().isoformat(timespec='milliseconds'),
    )
    return storage


def test_upgrade_manager_restores_backup(tmp_path):
    db_path = tmp_path / Path('v17_log.db')
    upgrade_manager = UpgradeManager(db_filename=db_path)

    old_db_filename = tmp_path / Path('v16_log.db')
    storage = None
    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
        storage = setup_storage(old_db_filename)

        with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=16):
            storage.update_version()

        upgrade_manager.run()

    # Once restored, the state changes written above should be
    # in the restored database
    storage = SQLiteStorage(str(db_path), JSONSerializer())
    state_change_record = storage.get_latest_state_change_by_data_field(
        {'_type': 'raiden.transfer.state_change.ActionInitChain'},
    )
    assert state_change_record.data is not None
    assert not old_db_filename.exists()
    assert Path(str(old_db_filename).replace('_log.db', '_log.backup')).exists()
