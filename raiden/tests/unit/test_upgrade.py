import json
from contextlib import ExitStack
from datetime import datetime
from pathlib import Path
from unittest.mock import ANY, Mock, patch

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SerializedSQLiteStorage, SQLiteStorage
from raiden.tests.utils.migrations import create_fake_web3_for_block_hash
from raiden.utils.upgrades import UpgradeManager, get_db_version


def setup_storage(db_path):
    # For a raw ActionInitChain let's get the v18 one. It should be the same as v16
    state_changes_file = Path(__file__).parent / 'storage/migrations/data/v18_statechanges.json'
    state_changes_data = json.loads(state_changes_file.read_text())
    action_init_chain_data = json.dumps(state_changes_data[0][1])
    storage = SQLiteStorage(str(db_path))
    storage.write_state_change(
        state_change=action_init_chain_data,
        log_time=datetime.utcnow().isoformat(timespec='milliseconds'),
    )
    return storage


def test_upgrade_manager_restores_backup(tmp_path):
    db_path = tmp_path / Path('v17_log.db')

    old_db_filename = tmp_path / Path('v16_log.db')

    storage = setup_storage(old_db_filename)

    with patch('raiden.constants.RAIDEN_DB_VERSION', new=16):
        storage.update_version()
        storage.conn.close()

    web3, _ = create_fake_web3_for_block_hash(number_of_blocks=1)
    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
        UpgradeManager(db_filename=db_path, web3=web3).run()

    # Once restored, the state changes written above should be
    # in the restored database
    storage = SerializedSQLiteStorage(str(db_path), JSONSerializer())
    state_change_record = storage.get_latest_state_change_by_data_field(
        {'_type': 'raiden.transfer.state_change.ActionInitChain'},
    )
    assert state_change_record.data is not None
    assert not old_db_filename.exists()
    assert Path(str(old_db_filename).replace('_log.db', '_log.backup')).exists()


def test_sequential_version_numbers(tmp_path):
    """ Test that the version received by each migration
    function is sequentially incremented according to the
    version returned by the previous migration.
    Sequence of events:
    - The first migration runs and returns v16 as the
      version it upgraded the database to.
    - The next migration should receive the old_version
      as v16 returned previously.
    - the above goes on for subsequent migrations.
    """
    db_path = tmp_path / Path('v19_log.db')

    old_db_filename = tmp_path / Path('v16_log.db')

    upgrade_functions = [Mock(), Mock(), Mock()]

    upgrade_functions[0].return_value = 17
    upgrade_functions[1].return_value = 18
    upgrade_functions[2].return_value = 19

    with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=16):
        storage = setup_storage(old_db_filename)
        storage.update_version()
        storage.conn.close()

    with ExitStack() as stack:
        stack.enter_context(patch(
            'raiden.utils.upgrades.UPGRADES_LIST',
            new=upgrade_functions,
        ))
        stack.enter_context(patch(
            'raiden.constants.RAIDEN_DB_VERSION',
            new=19,
        ))
        older_db_file = stack.enter_context(patch('raiden.utils.upgrades.older_db_file'))
        older_db_file.return_value = str(old_db_filename)

        UpgradeManager(db_filename=db_path).run()

        upgrade_functions[0].assert_called_once_with(ANY, 16, 19, web3=None)
        upgrade_functions[1].assert_called_once_with(ANY, 17, 19, web3=None)
        upgrade_functions[2].assert_called_once_with(ANY, 18, 19, web3=None)

        assert get_db_version(str(db_path)) == 19
