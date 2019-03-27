import os
import shutil
import sqlite3
from contextlib import closing
from glob import glob
from pathlib import Path

import filelock
import structlog

from raiden.constants import RAIDEN_DB_VERSION
from raiden.storage.migrations.v16_to_v17 import upgrade_v16_to_v17
from raiden.storage.migrations.v17_to_v18 import upgrade_v17_to_v18
from raiden.storage.migrations.v18_to_v19 import upgrade_v18_to_v19
from raiden.storage.migrations.v19_to_v20 import upgrade_v19_to_v20
from raiden.storage.sqlite import SQLiteStorage
from raiden.storage.versions import VERSION_RE, older_db_file
from raiden.utils.typing import Callable, NamedTuple, Optional


class UpgradeRecord(NamedTuple):
    from_version: int
    function: Callable


UPGRADES_LIST = [
    UpgradeRecord(
        from_version=16,
        function=upgrade_v16_to_v17,
    ),
    UpgradeRecord(
        from_version=17,
        function=upgrade_v17_to_v18,
    ),
    UpgradeRecord(
        from_version=18,
        function=upgrade_v18_to_v19,
    ),
    UpgradeRecord(
        from_version=19,
        function=upgrade_v19_to_v20,
    ),
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


def get_db_version(db_filename: Path) -> Optional[int]:
    """Return the version value stored in the db or None."""

    # Do not create an empty database
    if not db_filename.exists():
        return None

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
        cursor.execute('SELECT value FROM settings WHERE name="version";')
        result = cursor.fetchone()
    except sqlite3.OperationalError:
        raise RuntimeError(
            'Corrupted database. Database does not the settings table.',
        )

    if not result:
        raise RuntimeError(
            'Corrupted database. Settings table does not contain an entry the db version.',
        )

    return int(result[0])


def _run_upgrade_func(storage: SQLiteStorage, func: Callable, version: int, **kwargs) -> int:
    """ Run the migration function, store the version and advance the version. """
    new_version = func(storage, version, RAIDEN_DB_VERSION, **kwargs)
    update_version(storage, new_version)
    return new_version


def _backup_old_db(filename: str):
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

    def __init__(self, db_filename: str, **kwargs):
        base_name = os.path.basename(db_filename)
        match = VERSION_RE.match(base_name)
        assert match, f'Database name "{base_name}" does not match our format'

        self._current_version = match.group(1)
        self._current_db_filename = Path(db_filename)
        self._kwargs = kwargs

    def run(self):
        """
        The `_current_db_filename` is going to hold the filename of the database
        with the new version. However, the previous version's data
        is going to exist in a file whose name contains the old version.
        Therefore, running the migration means that we have to copy
        all data to the current version's database and execute the migration
        functions.
        """
        paths = glob(f'{self._current_db_filename.parent}/v*_log.db')
        older_file = older_db_file(paths)

        if older_file is None or older_file == str(self._current_db_filename):
            return

        old_db_filename = Path(older_file)

        with get_file_lock(old_db_filename), get_file_lock(self._current_db_filename):
            if self._current_db_filename.exists():
                db_version = get_db_version(self._current_db_filename)

                # The current version matches our target version, nothing to do.
                if db_version == RAIDEN_DB_VERSION:
                    return

                if db_version > RAIDEN_DB_VERSION:
                    raise RuntimeError(
                        f'Database version higher then expected. '
                        f'It is {db_version} should be {self._current_version}',
                    )

                # The version number in the database is smaller then the
                # current target, this means the migration failed to execute on
                # the last iteration, delete the partially upgraded database
                # and start again.
                self._delete_current_db()

            older_version = get_db_version(old_db_filename)
            if not older_version:
                # There are no older versions to upgrade from.
                return

            _copy(str(old_db_filename), str(self._current_db_filename))

            storage = SQLiteStorage(str(self._current_db_filename))

            log.debug(f'Upgrading database from {older_version} to v{RAIDEN_DB_VERSION}')

            try:
                target_version = older_version
                with storage.transaction():
                    for upgrade_record in UPGRADES_LIST:
                        if upgrade_record.from_version < target_version:
                            continue

                        target_version = _run_upgrade_func(
                            storage,
                            upgrade_record.function,
                            upgrade_record.from_version,
                            **self._kwargs,
                        )

                    update_version(storage, RAIDEN_DB_VERSION)
                    # Prevent the upgrade from happening on next restart
                    _backup_old_db(str(old_db_filename))
            except Exception as e:
                self._delete_current_db()
                log.error(f'Failed to upgrade database: {str(e)}')
                raise

            storage.conn.close()

    def _delete_current_db(self):
        os.remove(str(self._current_db_filename))
