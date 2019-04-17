import os
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
from raiden.storage.migrations.v20_to_v21 import upgrade_v20_to_v21
from raiden.storage.sqlite import SQLiteStorage
from raiden.storage.versions import VERSION_RE, filter_db_names, latest_db_file
from raiden.utils.typing import Callable, List, NamedTuple, Optional


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
    UpgradeRecord(
        from_version=20,
        function=upgrade_v20_to_v21,
    ),
]


log = structlog.get_logger(__name__)


def get_file_lock(db_filename: Path):
    lock_file_name = f'{db_filename}.lock'
    return filelock.FileLock(lock_file_name)


def update_version(storage: SQLiteStorage, version: int):
    cursor = storage.conn.cursor()
    cursor.execute(
        'INSERT OR REPLACE INTO settings(name, value) VALUES("version", ?)',
        (str(version), ),
    )


def get_file_version(db_path: str) -> int:
    match = VERSION_RE.match(os.path.basename(db_path))
    assert match, f'Database name "{db_path}" does not match our format'
    file_version = int(match.group(1))
    return file_version


def get_db_version(db_filename: Path) -> Optional[int]:
    """Return the version value stored in the db or None."""

    assert os.path.exists(db_filename)

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


def delete_dbs_with_failed_migrations(valid_db_names: List[str]) -> None:
    for db_path in valid_db_names:
        file_version = get_file_version(db_path)

        with get_file_lock(db_path):
            db_version = get_db_version(db_path)

            # The version matches, nothing to do.
            if db_version == file_version:
                continue

            elif db_version > file_version:
                raise RuntimeError(
                    f'Impossible database version. '
                    f'The database {db_path} has too high a version ({db_version}), '
                    f'this should never happen.',
                )

            # The version number in the database is smaller then the current
            # target, this means that a migration failed to execute and the db
            # is partially upgraded.
            else:
                os.remove(db_path)


class UpgradeManager:
    """ Run migrations when a database upgrade is necesary.

    Skip the upgrade if either:

    - There is no previous DB
    - There is a current DB file and the version in settings matches.

    Upgrade procedure:

    - Delete corrupted databases.
    - Copy the old file to the latest version (e.g. copy version v16 as v18).
    - In a transaction: Run every migration. Each migration must decide whether
      to proceed or not.
    """

    def __init__(self, db_filename: str, **kwargs):
        base_name = os.path.basename(db_filename)
        match = VERSION_RE.match(base_name)
        assert match, f'Database name "{base_name}" does not match our format'

        self._current_db_filename = Path(db_filename)
        self._current_version = get_file_version(db_filename)
        self._kwargs = kwargs

    def run(self):
        # First clear up any partially upgraded databases.
        #
        # A database will be partially upgraded if the process receives a
        # SIGKILL/SIGINT while executing migrations. NOTE: It's very probable
        # the content of the database remains consistent, because the upgrades
        # are executed inside a migration, however making a second copy of the
        # database does no harm.
        paths = glob(f'{self._current_db_filename.parent}/v*_log.db')
        valid_db_names = filter_db_names(paths)
        delete_dbs_with_failed_migrations(valid_db_names)

        # At this point we know every file version and db version match
        # (assuming there are no concurrent runs).
        paths = glob(f'{self._current_db_filename.parent}/v*_log.db')
        valid_db_names = filter_db_names(paths)
        latest_db_path = latest_db_file(valid_db_names)

        # First run, there is no database file available
        if latest_db_path is None:
            return

        file_version = get_file_version(latest_db_path)

        # The latest version matches our target version, nothing to do.
        if file_version == RAIDEN_DB_VERSION:
            return

        if file_version > RAIDEN_DB_VERSION:
            raise RuntimeError(
                f'Conflicting database versions detected, latest db version is {file_version}, '
                f'Raiden client version is {RAIDEN_DB_VERSION}.'
                f'\n\n'
                f'Running a downgraded version of Raiden after an upgrade is not supported, '
                f'because the transfers done with the new client are not understandable by the '
                f'older.',
            )

        self._upgrade(
            target_file=str(self._current_db_filename),
            from_file=latest_db_path,
            from_version=file_version,
        )

    def _upgrade(self, target_file: str, from_file: str, from_version: int):
        with get_file_lock(from_file), get_file_lock(target_file):
            _copy(from_file, target_file)

            storage = SQLiteStorage(target_file)

            log.debug(f'Upgrading database from {from_version} to {RAIDEN_DB_VERSION}')

            try:
                version_iteration = from_version

                with storage.transaction():
                    for upgrade_record in UPGRADES_LIST:
                        if upgrade_record.from_version < from_version:
                            continue

                        version_iteration = upgrade_record.function(
                            storage=storage,
                            old_version=version_iteration,
                            current_version=RAIDEN_DB_VERSION,
                            **self._kwargs,
                        )

                    update_version(storage, RAIDEN_DB_VERSION)
            except BaseException as e:
                log.error(f'Failed to upgrade database: {e}')
                raise

            storage.conn.close()
