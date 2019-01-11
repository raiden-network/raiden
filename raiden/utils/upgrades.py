import importlib
import os
import shutil
from pathlib import Path

from raiden.exceptions import RaidenDBUpgradeBackupError, RaidenDBUpgradeExecutionError
from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage


class UpgradeManager:
    """ This class is responsible for figuring out which migrations
    need to be executed in order to bring the database up to date
    with the current implementation.
    """

    MIGRATIONS_MODULE = 'raiden.utils.migrations'

    def __init__(
            self,
            db_filename: str,
            current_version: int,
            new_version: int,
    ):
        self._current_version = current_version
        self._new_version = new_version
        self._db_filename = Path(db_filename)
        self._backup_filename = self._db_filename.parent / Path(
            f'version{self._current_version}_db.backup',
        )

    def run(self):
        storage = SQLiteStorage(str(self._db_filename), JSONSerializer())

        self._backup()

        for version in range(self._current_version, self._new_version):
            upgrade_module_name = f'v{version}_to_v{version+1}'
            upgrade_module = self._load_module(upgrade_module_name)
            upgrade_module.upgrade(storage)

    def restore_backup(self):
        os.remove(str(self._db_filename))
        shutil.copy(str(self._backup_filename), str(self._db_filename))

    def _backup(self):
        shutil.copy(str(self._db_filename), str(self._backup_filename))

        if not self._backup_filename.exists():
            raise RaidenDBUpgradeBackupError()

    def _load_module(self, module_name):
        try:
            return importlib.import_module(
                f'{self.MIGRATIONS_MODULE}.{module_name}',
            )
        except ImportError:
            raise RaidenDBUpgradeExecutionError(
                f'Could not import module {module_name}',
            )
