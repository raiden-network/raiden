from unittest.mock import patch

import pytest

from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage


def test_transaction_commit(tmp_path):
    filename = f"v{RAIDEN_DB_VERSION}_db.log"
    storage = SQLiteStorage(f"{tmp_path}/{filename}")

    with storage.transaction():
        with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=1000):
            storage.update_version()

    assert storage.get_version() == 1000


def test_transaction_rollback(tmp_path):
    filename = f"v{RAIDEN_DB_VERSION}_db.log"
    storage = SQLiteStorage(f"{tmp_path}/{filename}")
    storage.update_version()

    assert storage.get_version() == RAIDEN_DB_VERSION

    with pytest.raises(KeyboardInterrupt):
        with storage.transaction():
            with patch("raiden.storage.sqlite.RAIDEN_DB_VERSION", new=1000):
                storage.update_version()
                raise KeyboardInterrupt()
    assert storage.get_version() == RAIDEN_DB_VERSION
