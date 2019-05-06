from unittest.mock import MagicMock

import pytest

from raiden.storage.versions import VERSION_RE
from raiden.utils.upgrades import delete_dbs_with_failed_migrations


def _return_valid_db_version(db_filename):
    version = int(VERSION_RE.match(db_filename).group(1))
    return version


def _return_smaller_db_version(db_filename):
    version = int(VERSION_RE.match(db_filename).group(1)) - 1
    return version


def _return_higher_db_version(db_filename):
    version = int(VERSION_RE.match(db_filename).group(1)) + 1
    return version


class GetLockMock:
    # pylint: disable=unused-argument
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        pass

    def __exit__(self, a_, b_, c_):
        pass


def test_delete_dbs_with_failed_migrations(monkeypatch):
    """Only sqlite databases which have an older version in the settings table
    in respect to *its* filename should be removed.

    This is testing that nothing else is removed, since it's crucial that the
    wrong database is not deleted.
    """
    file_names = ["v1_log.db", "v11_log.db", "v9_log.db", "v9999_log.db"]

    exists_mock = MagicMock(return_value=True)
    monkeypatch.setattr("raiden.utils.upgrades.get_file_lock", GetLockMock)

    with monkeypatch.context() as m:
        remove_mock = MagicMock()

        m.setattr("raiden.utils.upgrades.get_db_version", _return_valid_db_version)
        m.setattr("raiden.utils.upgrades.os.path.exists", exists_mock)
        m.setattr("raiden.utils.upgrades.os.remove", remove_mock)

        delete_dbs_with_failed_migrations(list(file_names))
        remove_mock.assert_not_called()

    with monkeypatch.context() as m:
        remove_mock = MagicMock()

        m.setattr("raiden.utils.upgrades.get_db_version", _return_higher_db_version)
        m.setattr("raiden.utils.upgrades.os.path.exists", exists_mock)
        m.setattr("raiden.utils.upgrades.os.remove", remove_mock)

        with pytest.raises(RuntimeError):
            delete_dbs_with_failed_migrations(list(file_names))

        remove_mock.assert_not_called()

    with monkeypatch.context() as m:
        remove_mock = MagicMock()

        m.setattr("raiden.utils.upgrades.get_db_version", _return_smaller_db_version)
        m.setattr("raiden.utils.upgrades.os.path.exists", exists_mock)
        m.setattr("raiden.utils.upgrades.os.remove", remove_mock)

        delete_dbs_with_failed_migrations(list(file_names))

        for value in file_names:
            remove_mock.assert_any_call(value)
