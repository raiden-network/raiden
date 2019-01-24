import os
import shutil
from pathlib import Path

import structlog

from raiden.exceptions import RaidenDBUpgradeBackupError
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import RAIDEN_DB_VERSION, SQLiteStorage
from raiden.utils.migrations.v16_to_v17 import upgrade_initiator_manager

UPGRADES_LIST = [
    upgrade_initiator_manager,
]


log = structlog.get_logger(__name__)


class UpgradeManager:
    """ This class is responsible for figuring out which migrations
    need to be executed in order to bring the database up to date
    with the current implementation.
    """
    def __init__(self, db_filename: str):
        self._db_filename = Path(db_filename)

    def run(self):
        storage = SQLiteStorage(str(self._db_filename), JSONSerializer())

        self._old_version = storage.get_version()
        self._current_version = RAIDEN_DB_VERSION
        self._backup_filename = self._db_filename.parent / Path(
            f'version{self._current_version}_db.backup',
        )

        if self._current_version <= self._old_version:
            return

        log.debug(f'Upgrading database from v{self._old_version} to v{self._current_version}')

        self._backup()

        for upgrade_func in UPGRADES_LIST:
            upgrade_func(storage, self._old_version, self._current_version)

        storage.update_version()

    def restore_backup(self):
        os.remove(str(self._db_filename))
        shutil.copy(str(self._backup_filename), str(self._db_filename))

    def _backup(self):
        shutil.copy(str(self._db_filename), str(self._backup_filename))

        if not self._backup_filename.exists():
            raise RaidenDBUpgradeBackupError()
