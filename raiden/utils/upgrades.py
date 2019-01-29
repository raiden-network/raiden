import os
import shutil
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path

import filelock
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


def update_version(cursor):
    cursor.execute(
        'INSERT OR REPLACE INTO settings(name, value) VALUES(?, ?)',
        ('version', str(RAIDEN_DB_VERSION)),
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


@contextmanager
def in_transaction(cursor):
    try:
        yield
        cursor.execute('COMMIT')
    except Exception as e:
        cursor.execute('ROLLBACK')
        log.error(f'Failed to upgrade database: {str(e)}')
        raise


class UpgradeManager:
    """ This class is responsible for figuring out which migrations
    need to be executed in order to bring the database up to date
    with the current implementation.
    Here's how upgrade cycle looks like. Assuming:
    (a) The user used to run version 16
    (b) Has downloaded the newer version, say 18.
    So the upgrade would:
    1. Look to see what older databases we have.
    2. If no previous db file is found, it would skip the upgrade since no older DB was found.
    3. If the database for the current version exists, skip the upgrade since it's been
       done already.
    4. If there is no file for the current database, copy the old one (v16) to (v18).
    5. Run every migration, where every migration will get the old version and the new version.
       The migration will compare versions against the version it's upgrading and decide whether
       to proceed with the migration or not.
    6. Once all migration functions are executed, the transaction is committed and the
       database is ready.
    7. In case of an exception, revert all changes and delete the DB file from filesystem
       to prevent (3).
       from retrying the migration on the next restart.
    8. If the migration is successful, rename the older DB to prevent (1) from detecting it again.
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
        old_db_filename = older_db_file(str(self._current_db_filename.parent))

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

            self._copy(str(old_db_filename), str(self._current_db_filename))

            storage = SQLiteStorage(str(self._current_db_filename), JSONSerializer())

            log.debug(f'Upgrading database to v{RAIDEN_DB_VERSION}')

            cursor = storage.conn.cursor()
            with in_transaction(cursor):
                try:
                    for upgrade_func in UPGRADES_LIST:
                        upgrade_func(cursor, older_version, RAIDEN_DB_VERSION)

                    update_version(cursor)
                    # Prevent the upgrade from happening on next restart
                    self._backup_old_db(old_db_filename)
                except RaidenDBUpgradeError:
                    self._delete_current_db()
                    raise

    def _backup_old_db(self, filename):
        backup_name = filename.replace('_log.db', '_log.backup')
        shutil.move(filename, backup_name)

    def _delete_current_db(self):
        os.remove(str(self._current_db_filename))

    def _copy(self, old_db_filename, current_db_filename):
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
