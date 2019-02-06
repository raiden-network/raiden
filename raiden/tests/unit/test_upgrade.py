import random
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from unittest.mock import ANY, Mock, patch

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.state_change import ActionInitChain
from raiden.utils.upgrades import UpgradeManager, get_db_version


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

    storage = setup_storage(old_db_filename)

    with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=16):
        storage.update_version()

    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
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


def test_sequential_version_numbers(tmp_path):
    db_path = tmp_path / Path('v19_log.db')
    upgrade_manager = UpgradeManager(db_filename=db_path)

    old_db_filename = tmp_path / Path('v16_log.db')
    storage = None

    upgrade_functions = [Mock(), Mock(), Mock()]

    upgrade_functions[0].return_value = 17
    upgrade_functions[1].return_value = 18
    upgrade_functions[2].return_value = 19

    with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=16):
        storage = setup_storage(old_db_filename)
        storage.update_version()

    with ExitStack() as stack:
        stack.enter_context(patch(
            'raiden.utils.upgrades.UPGRADES_LIST',
            new=upgrade_functions,
        ))
        stack.enter_context(patch(
            'raiden.utils.upgrades.RAIDEN_DB_VERSION',
            new=19,
        ))
        older_db_file = stack.enter_context(patch('raiden.utils.upgrades.older_db_file'))
        older_db_file.return_value = str(old_db_filename)

        upgrade_manager.run()

        upgrade_functions[0].assert_called_once_with(ANY, 16, 19)
        upgrade_functions[1].assert_called_once_with(ANY, 17, 19)
        upgrade_functions[2].assert_called_once_with(ANY, 18, 19)

        assert get_db_version(str(db_path)) == 19
