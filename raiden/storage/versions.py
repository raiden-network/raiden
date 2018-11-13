import os
import re
from glob import glob

from raiden.utils import typing

from .sqlite import RAIDEN_DB_VERSION

VERSION_RE = re.compile("^v(\d+).*")


def older_db_file(database_base_path: str) -> typing.Optional[str]:
    """ Returns the path to a database file that belong to the previous version
    of the schema.
    """
    database_base_path = os.path.expanduser(database_base_path)
    db_files = glob(f'{database_base_path}/**/*.db', recursive=True)
    for db_file in db_files:
        expanded_name = os.path.basename(db_file)
        matches = VERSION_RE.search(expanded_name)
        if not matches:
            continue
        try:
            version = int(matches.group(1))
        except ValueError:
            continue

        if version < RAIDEN_DB_VERSION:
            return expanded_name

    return None
