import json
from datetime import datetime
from pathlib import Path
from unittest.mock import ANY, Mock, patch

import raiden.utils.upgrades
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils.migrations import create_fake_web3_for_block_hash
from raiden.utils.upgrades import VERSION_RE, UpgradeManager, UpgradeRecord, get_db_version


def test_version_regex():
    assert VERSION_RE.match('v0_log.db')
    assert VERSION_RE.match('v11_log.db')
    assert VERSION_RE.match('v9999_log.db')

    assert not VERSION_RE.match('v0_log.dba')
    assert not VERSION_RE.match('v0_log.db1')
    assert not VERSION_RE.match('v0a_log.db')
    assert not VERSION_RE.match('va1_log.db')
    assert not VERSION_RE.match('v9999_logb.db')
    assert not VERSION_RE.match('0_log.db')
    assert not VERSION_RE.match('v0_log')


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


def test_no_upgrade_executes_if_already_upgraded(tmp_path):
    # Setup multiple old databases
    for version in [16, 17, 18, 19]:
        old_db_filename = tmp_path / Path(f'v{version}_log.db')

        storage = setup_storage(old_db_filename)

        with patch('raiden.utils.upgrades.RAIDEN_DB_VERSION', new=version):
            storage.update_version()
            storage.conn.close()

    db_path = tmp_path / Path('v19_log.db')

    with patch('raiden.utils.upgrades._run_upgrade_func') as upgrade_mock:
        UpgradeManager(db_filename=db_path).run()
        # Oldest database is of the same version as the current, no migrations should execute
        assert not upgrade_mock.called


def test_upgrade_executes_necessary_migration_functions(tmp_path, monkeypatch):
    old_db_filename = tmp_path / Path(f'v18_log.db')

    storage = setup_storage(old_db_filename)
    with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=18):
        storage.update_version()
        storage.conn.close()

    db_path = tmp_path / Path('v20_log.db')

    upgrade_functions = []
    for i in range(16, 20):
        mock = Mock()
        mock.return_value = i + 1
        upgrade_functions.append(UpgradeRecord(
            from_version=i,
            function=mock,
        ))

    with monkeypatch.context() as m:
        m.setattr(
            raiden.utils.upgrades,
            'UPGRADES_LIST',
            upgrade_functions,
        )
        m.setattr(
            raiden.utils.upgrades,
            'RAIDEN_DB_VERSION',
            19,
        )

        UpgradeManager(db_filename=db_path).run()

    assert upgrade_functions[0].function.call_count == 0
    assert upgrade_functions[1].function.call_count == 0
    assert upgrade_functions[2].function.call_count == 1
    assert upgrade_functions[3].function.call_count == 1


def test_upgrade_manager_restores_backup(tmp_path, monkeypatch):
    db_path = tmp_path / Path('v17_log.db')

    old_db_filename = tmp_path / Path('v16_log.db')

    storage = setup_storage(old_db_filename)

    with patch('raiden.utils.upgrades.RAIDEN_DB_VERSION', new=16):
        storage.update_version()
        storage.conn.close()

    upgrade_functions = [
        UpgradeRecord(
            from_version=16,
            function=Mock(),
        ),
    ]

    upgrade_functions[0].function.return_value = 17

    web3, _ = create_fake_web3_for_block_hash(number_of_blocks=1)
    with monkeypatch.context() as m:
        m.setattr(
            raiden.utils.upgrades,
            'UPGRADES_LIST',
            upgrade_functions,
        )
        m.setattr(
            raiden.utils.upgrades,
            'RAIDEN_DB_VERSION',
            19,
        )
        UpgradeManager(db_filename=db_path, web3=web3).run()

    # Once restored, the state changes written above should be
    # in the restored database
    storage = SQLiteStorage(str(db_path))
    state_change_record = storage.get_latest_state_change_by_data_field(
        {'_type': 'raiden.transfer.state_change.ActionInitChain'},
    )
    assert state_change_record.data is not None
    assert not old_db_filename.exists()
    assert Path(str(old_db_filename).replace('_log.db', '_log.backup')).exists()


def test_sequential_version_numbers(tmp_path, monkeypatch):
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

    upgrade_functions = []
    for i in range(16, 19):
        mock = Mock()
        mock.return_value = i + 1
        upgrade_functions.append(UpgradeRecord(
            from_version=i,
            function=mock,
        ))

    with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=16):
        storage = setup_storage(old_db_filename)
        storage.update_version()
        storage.conn.close()

    with monkeypatch.context() as m:
        def mock_older_db_file(paths):  # pylint: disable=unused-argument
            return old_db_filename

        m.setattr(
            raiden.utils.upgrades,
            'UPGRADES_LIST',
            upgrade_functions,
        )
        m.setattr(
            raiden.utils.upgrades,
            'RAIDEN_DB_VERSION',
            19,
        )
        m.setattr(
            raiden.utils.upgrades,
            'older_db_file',
            mock_older_db_file,
        )

        UpgradeManager(db_filename=db_path).run()

        upgrade_functions[0].function.assert_called_once_with(ANY, 16, 19)
        upgrade_functions[1].function.assert_called_once_with(ANY, 17, 19)
        upgrade_functions[2].function.assert_called_once_with(ANY, 18, 19)

        assert get_db_version(db_path) == 19
