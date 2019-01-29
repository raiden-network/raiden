import os
import shutil
import sqlite3
from pathlib import Path

import filelock
import sqlitebck
import structlog

from raiden.exceptions import RaidenDBUpgradeError
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage
from raiden.storage.versions import older_db_file
from raiden.utils.migrations.v16_to_v17 import upgrade_initiator_manager

UPGRADES_LIST = [
    upgrade_initiator_manager,
]


log = structlog.get_logger(__name__)


def get_file_lock(db_filename: Path):
    lock_file_name = f'{db_filename}.lock'
    return filelock.FileLock(lock_file_name)


def get_db_version(db_filename: Path):
    db_lock = get_file_lock(db_filename)
    with db_lock:
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


class UpgradeManager:
    """ This class is responsible for figuring out which migrations
    need to be executed in order to bring the database up to date
    with the current implementation.
    """
    def __init__(self, db_filename: str):
        self._current_db_filename = Path(db_filename)

    def run(self):
        """
        The `_current_db_filename` is going to hold the filename of the database
        with the new version. However, the previous version's data
        is going to exist in a file whose name contains the old version.
        Therefore, running the migration means that we have to copy
        all data to the current version's database, execute the migration
        functions.
        """
        if get_db_version(self._current_db_filename) == RAIDEN_DB_VERSION:
            # The current version has already been created / updraded.
            return
        else:
            # The version inside the current database was not the expected one.
            # Delete and re-run migration
            self._delete_current_db()

        old_version, old_db_filename = older_db_file(str(self._current_db_filename.parent))

        if not old_version:
            # There are no older versions to upgrade from.
            return

        self._copy(str(old_db_filename), str(self._current_db_filename))

        storage = SQLiteStorage(str(self._current_db_filename), JSONSerializer())

        log.debug(f'Upgrading database to v{RAIDEN_DB_VERSION}')

        storage.conn.isolation_level = None
        cursor = storage.conn.cursor()
        cursor.execute('BEGIN')
        try:
            for upgrade_func in UPGRADES_LIST:
                upgrade_func(cursor, old_version, RAIDEN_DB_VERSION)

            # COMMIT is going to be executed within update_version.
            storage.update_version()
            # Prevent the upgrade from happening on next restart
            self._backup_old_db(old_db_filename)
        except RaidenDBUpgradeError as e:
            cursor.execute('ROLLBACK')
            self._delete_current_db()
            log.error(f'Failed to upgrade database: {str(e)}')
            raise

    def _backup_old_db(self, filename):
        backup_name = filename.replace('_log.db', '_log.backup')
        with get_file_lock(filename):
            shutil.move(filename, backup_name)

    def _delete_current_db(self):
        os.remove(str(self._current_db_filename))

    def _copy(self, old_db_filename, current_db_filename):
        with get_file_lock(old_db_filename), get_file_lock(current_db_filename):
            old_conn = sqlite3.connect(
                old_db_filename,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            current_conn = sqlite3.connect(
                current_db_filename,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )

            sqlitebck.copy(old_conn, current_conn)

            old_conn.close()
            current_conn.close()
