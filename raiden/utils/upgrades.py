import os
import shutil
import sqlite3
from contextlib import closing
from pathlib import Path

import filelock
import structlog

from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage
from raiden.storage.versions import older_db_file
from raiden.utils.migrations.v16_to_v17 import upgrade_initiator_manager
from raiden.utils.migrations.v17_to_v18 import upgrade_mediators_with_waiting_transfer
from raiden.utils.typing import Callable

UPGRADES_LIST = [
    upgrade_initiator_manager,
    upgrade_mediators_with_waiting_transfer,
]


log = structlog.get_logger(__name__)


def get_file_lock(db_filename: Path):
    lock_file_name = f'{db_filename}.lock'
    return filelock.FileLock(lock_file_name)


def update_version(storage: SQLiteStorage, version: int):
    cursor = storage.conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO settings(name, value) VALUES(?, ?)',
        ('version', str(version)),
    )


def get_db_version(db_filename: Path):
    # Perform a query directly through SQL rather than using
    # storage.get_version()
    # as get_version will return the latest version if it doesn't
    # find a record in the database.
    conn = sqlite3.connect(
        str(db_filename),
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    cursor = conn.cursor()
    try:
        cursor.execute('SELECT value FROM settings WHERE name=?;', ('version',))
        query = cursor.fetchall()
        if len(query) == 0:
            return 0
        return int(query[0][0])
    except sqlite3.OperationalError:
        return 0


def _run_upgrade_func(cursor: sqlite3.Cursor, func: Callable, version: int) -> int:
    """ Run the migration function, store the version and advance the version. """
    new_version = func(cursor, version, RAIDEN_DB_VERSION)
    update_version(cursor, new_version)
    return new_version


def _backup_old_db(filename):
    backup_name = filename.replace('_log.db', '_log.backup')
    shutil.move(filename, backup_name)


def _copy(old_db_filename, current_db_filename):
    old_conn = sqlite3.connect(
        old_db_filename,
        detect_types=sqlite3.PARSE_DECLTYPES,
    )
    current_conn = sqlite3.connect(
        current_db_filename,
        detect_types=sqlite3.PARSE_DECLTYPES,
    )

    with closing(old_conn), closing(current_conn):
        old_conn.backup(current_conn)


class UpgradeManager:
    """ Run migrations when a database upgrade is necesary.

    Skip the upgrade if either:

    - There is no previous DB
    - There is a current DB file and the version in settings matches.

    Upgrade procedure:

    - Copy the old file to the latest version (e.g. copy version v16 as v18).
    - In a transaction: Run every migration. Each migration must decide whether
      to proceed or not.
    - If a single migration fails: The transaction is not commited and the DB
      copy is deleted.
    - If every migration succeeds: Rename the old DB.
    """

    def __init__(self, db_filename: str):
        self._current_db_filename = Path(db_filename)

    def run(self):
        """
        The `_current_db_filename` is going to hold the filename of the database
        with the new version. However, the previous version's data
        is going to exist in a file whose name contains the old version.
        Therefore, running the migration means that we have to copy
        all data to the current version's database and execute the migration
        functions.
        """
        old_db_filename = older_db_file(str(self._current_db_filename.parent))

        if old_db_filename is None:
            return

        with get_file_lock(old_db_filename), get_file_lock(self._current_db_filename):
            if get_db_version(self._current_db_filename) == RAIDEN_DB_VERSION:
                # The current version has already been created / updraded.
                return
            else:
                # The version inside the current database was not the expected one.
                # Delete and re-run migration
                self._delete_current_db()

            older_version = get_db_version(old_db_filename)
            if not older_version:
                # There are no older versions to upgrade from.
                return

            _copy(str(old_db_filename), str(self._current_db_filename))

            storage = SQLiteStorage(str(self._current_db_filename))

            log.debug(f'Upgrading database from {older_version} to v{RAIDEN_DB_VERSION}')

            try:
                with storage.transaction():
                    version_iteration = older_version
                    for upgrade_func in UPGRADES_LIST:
                        version_iteration = _run_upgrade_func(
                            storage,
                            upgrade_func,
                            version_iteration,
                        )

                    update_version(storage, RAIDEN_DB_VERSION)
                    # Prevent the upgrade from happening on next restart
                    _backup_old_db(old_db_filename)
            except Exception as e:
                self._delete_current_db()
                log.error(f'Failed to upgrade database: {str(e)}')
                raise

            storage.conn.close()

    def _delete_current_db(self):
        os.remove(str(self._current_db_filename))
