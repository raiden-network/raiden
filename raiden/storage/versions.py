import os
import re
from glob import glob

from .sqlite import RAIDEN_DB_VERSION

VERSION_RE = re.compile("^v(\d+).*")


def older_db_files_exist(database_base_path: str):
    """ Check if the directory contains database files that
    belong to the previous version of the schema. """
    database_base_path = os.path.expanduser(database_base_path)
    db_files = glob(f'{database_base_path}/**/*.db', recursive=True)
    for db_file in db_files:
        matches = VERSION_RE.search(os.path.basename(db_file))
        if not matches:
            continue
        try:
            version = int(matches.group(1))
        except ValueError:
            continue

        if version < RAIDEN_DB_VERSION:
            return True

    return False
