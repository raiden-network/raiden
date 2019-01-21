import os
import shutil
from pathlib import Path

from raiden.exceptions import RaidenDBUpgradeBackupError
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.utils.migrations.v16_to_v17 import upgrade_initiator_manager

UPGRADES_LIST = [
    upgrade_initiator_manager,
]


class UpgradeManager:
    """ This class is responsible for figuring out which migrations
    need to be executed in order to bring the database up to date
    with the current implementation.
    """
    def __init__(
            self,
            db_filename: str,
            old_version: int,
            current_version: int,
    ):
        self._old_version = old_version
        self._current_version = current_version
        self._db_filename = Path(db_filename)
        self._backup_filename = self._db_filename.parent / Path(
            f'version{self._current_version}_db.backup',
        )

    def run(self):
        storage = SQLiteStorage(str(self._db_filename), JSONSerializer())

        self._backup()

        for upgrade_func in UPGRADES_LIST:
            upgrade_func(storage, self._old_version, self._current_version)

    def restore_backup(self):
        os.remove(str(self._db_filename))
        shutil.copy(str(self._backup_filename), str(self._db_filename))

    def _backup(self):
        shutil.copy(str(self._db_filename), str(self._backup_filename))

        if not self._backup_filename.exists():
            raise RaidenDBUpgradeBackupError()
