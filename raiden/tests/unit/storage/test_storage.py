import os.path
from pathlib import Path
from unittest.mock import patch

import pytest

from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage
from raiden.utils.upgrades import UpgradeManager, UpgradeRecord


def test_transaction_commit(tmp_path):
    filename = f"v{RAIDEN_DB_VERSION}_log.db"
    storage = SQLiteStorage(Path(f"{tmp_path}/{filename}"))

    with storage.transaction():
        with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=1000):
            storage.update_version()

    assert storage.get_version() == 1000


def test_transaction_rollback(tmp_path):
    filename = f"v{RAIDEN_DB_VERSION}_log.db"
    db_path = Path(tmp_path / filename)
    storage = SQLiteStorage(db_path)
    storage.update_version()

    assert storage.get_version() == RAIDEN_DB_VERSION

    with pytest.raises(RuntimeError):
        with storage.transaction():
            with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=1000):
                storage.update_version()
                raise RuntimeError()

    assert storage.get_version() == RAIDEN_DB_VERSION


def test_upgrade_manager_transaction_rollback(tmp_path, monkeypatch):
    FORMAT = os.path.join(tmp_path, "v{}_log.db")

    def failure(**kwargs):  # pylint: disable=unused-argument
        raise RuntimeError()

    # Create the db to be upgraded
    with monkeypatch.context() as m:
        m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 1)
        storage = SQLiteStorage(Path(FORMAT.format(1)))
        storage.update_version()
        del storage

    # This should not fail with 'OperationalError'
    with pytest.raises(RuntimeError):
        with monkeypatch.context() as m:
            m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 2)
            upgrade_list = [UpgradeRecord(from_version=1, function=failure)]
            m.setattr("raiden.utils.upgrades.UPGRADES_LIST", upgrade_list)
            manager = UpgradeManager(Path(FORMAT.format(2)))
            manager.run()

    storage = SQLiteStorage(Path(FORMAT.format(2)))
    assert storage.get_version() == 1, "The upgrade must have failed"


def test_regression_delete_should_not_commit_the_upgrade_transaction(tmp_path, monkeypatch):
    FORMAT = os.path.join(tmp_path, "v{}_log.db")

    def failure(storage, **kwargs):  # pylint: disable=unused-argument
        storage.delete_state_changes([1, 2])

    # Create the db to be upgraded
    with monkeypatch.context() as m:
        m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 1)
        storage = SQLiteStorage(Path(FORMAT.format(1)))
        storage.update_version()
        del storage

    with pytest.raises(ValueError):
        # This should not fail with 'OperationalError'
        with monkeypatch.context() as m:
            m.setattr("raiden.storage.sqlite.RAIDEN_DB_VERSION", 2)
            upgrade_list = [UpgradeRecord(from_version=1, function=failure)]
            m.setattr("raiden.utils.upgrades.UPGRADES_LIST", upgrade_list)
            manager = UpgradeManager(Path(FORMAT.format(2)))
            manager.run()

    storage = SQLiteStorage(Path(FORMAT.format(2)))
    assert storage.get_version() == 1, "The upgrade must have failed"
