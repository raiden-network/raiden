import random
import time
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
    time.sleep(1)
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
    db_path = tmp_path / Path('test.db')
    upgrade_manager = UpgradeManager(db_filename=db_path)

    with patch('raiden.storage.sqlite.SQLiteStorage.get_version') as get_version:
        get_version.return_value = 16
        upgrade_manager.run()

    assert upgrade_manager._backup_filename.exists()

    # Write some state changes into the backup DB file
    setup_storage(str(upgrade_manager._backup_filename))

    upgrade_manager.restore_backup()

    # Once restored, the state changes written above should be
    # in the restored database
    storage = SQLiteStorage(str(db_path), JSONSerializer())
    state_change_record = storage.get_latest_state_change_by_data_field(
        {'_type': 'raiden.transfer.state_change.ActionInitChain'},
    )
    assert state_change_record.data is not None
