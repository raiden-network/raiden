import os.path
from collections import defaultdict
from datetime import datetime
from unittest.mock import patch

import pytest

from raiden.storage.sqlite import RAIDEN_DB_VERSION, MatrixStorage, SQLiteStorage
from raiden.storage.utils import make_db_connection
from raiden.tests.utils.factories import make_address
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def test_transaction_commit(tmp_path):
    filename = f"v{RAIDEN_DB_VERSION}_log.db"
    conn = make_db_connection(f"{tmp_path}/{filename}")
    storage = SQLiteStorage(conn)

    with storage.transaction():
        with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=1000):
            storage.update_version()

    assert storage.get_version() == 1000
    storage.close()


def test_transaction_rollback(tmp_path):
    filename = f"v{RAIDEN_DB_VERSION}_log.db"
    db_path = os.path.join(tmp_path, filename)
    conn = make_db_connection(db_path)
    storage = SQLiteStorage(conn)
    storage.update_version()

    assert storage.get_version() == RAIDEN_DB_VERSION

    with pytest.raises(RuntimeError):
        with storage.transaction():
            with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=1000):
                storage.update_version()
                raise RuntimeError()
    assert storage.get_version() == RAIDEN_DB_VERSION
    storage.close()


def test_upgrade_manager_transaction_rollback(tmp_path, monkeypatch):
    FORMAT = os.path.join(tmp_path, "v{}_log.db")

    def failure(**kwargs):  # pylint: disable=unused-argument
        raise RuntimeError()

    # Create the db to be upgraded
    with monkeypatch.context() as m:
        m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 1)
        conn = make_db_connection(FORMAT.format(1))
        storage = SQLiteStorage(conn)
        storage.update_version()
        storage.close()
        del storage

    # This should not fail with 'OperationalError'
    with pytest.raises(RuntimeError):
        with monkeypatch.context() as m:
            m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 2)
            upgrade_list = [UpgradeRecord(from_version=1, function=failure)]
            m.setattr("raiden.utils.upgrades.UPGRADES_LIST", upgrade_list)
            manager = UpgradeManager(FORMAT.format(2))
            manager.run()

    conn = make_db_connection(FORMAT.format(2))
    storage = SQLiteStorage(conn)
    assert storage.get_version() == 1, "The upgrade must have failed"
    storage.close()


def test_regression_delete_should_not_commit_the_upgrade_transaction(tmp_path, monkeypatch):
    FORMAT = os.path.join(tmp_path, "v{}_log.db")

    def failure(storage, **kwargs):  # pylint: disable=unused-argument
        storage.delete_state_changes([1, 2])

    # Create the db to be upgraded
    with monkeypatch.context() as m:
        m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 1)
        conn = make_db_connection(FORMAT.format(1))
        storage = SQLiteStorage(conn)
        storage.update_version()
        storage.close()
        del storage

    with pytest.raises(ValueError):
        # This should not fail with 'OperationalError'
        with monkeypatch.context() as m:
            m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 2)
            upgrade_list = [UpgradeRecord(from_version=1, function=failure)]
            m.setattr("raiden.utils.upgrades.UPGRADES_LIST", upgrade_list)
            manager = UpgradeManager(FORMAT.format(2))
            manager.run()

    conn = make_db_connection(FORMAT.format(2))
    storage = SQLiteStorage(conn)
    assert storage.get_version() == 1, "The upgrade must have failed"
    storage.close()


def test_get_matrix_userids_for_address():
    conn = make_db_connection()
    storage = MatrixStorage(conn)
    timestamp = datetime.utcnow()
    address = make_address()
    user_ids = {
        "@0xdd2a8d3a434273289b4e9b0c20ad61b705d7d61f:localhost:8500",
        "@0xc24acbf411290aff4e0294d956fb3e5f82af4d8e:localhost:8501",
    }
    assert storage.get_matrix_userids_and_addresses() == defaultdict(set)
    assert storage.get_matrix_roomids_for_address(address) == {}

    storage.write_matrix_userids_for_address(
        address=address, user_ids=user_ids, timestamp=timestamp
    )
    room_ids_to_aliases = {
        "!EccQWEAMFrOhVqPgYt:localhost:8500": "#raiden_17_0x2af15b_0x7cfc0b:localhost:8500",
        "!lWOxcxArgnXltwsAaP:localhost:8501": "#raiden_17_0x2af15b_0x7cfc0b:localhost:8501",
    }
    storage.write_matrix_roomids_for_address(
        address=address, room_ids_to_aliases=room_ids_to_aliases, timestamp=timestamp
    )

    stored_user_ids_for_address = storage.get_matrix_userids_and_addresses()
    stored_room_ids_to_aliases = storage.get_matrix_roomids_for_address(address)

    assert stored_user_ids_for_address[address] == set(user_ids)
    assert stored_room_ids_to_aliases == room_ids_to_aliases
    storage.database.close()
