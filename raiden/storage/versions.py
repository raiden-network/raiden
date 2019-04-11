import os.path
import re

from raiden.utils.typing import List, Optional

VERSION_RE = re.compile(r'^v(\d+)_log[.]db$')


def latest_db_file(paths: List[str]) -> Optional[str]:
    """Returns the path with the highest `version` number.

    Raises:
        AssertionError: If any of the `paths` in the list is an invalid name.

    Args:
        paths: A list of file names.
    """
    dbs = {}
    for db_path in paths:
        matches = VERSION_RE.match(os.path.basename(db_path))
        assert matches, f'Invalid path name {db_path}'

        try:
            version = int(matches.group(1))
        except ValueError:
            continue

        dbs[version] = db_path

    if dbs:
        highest_version = sorted(dbs)[-1]
        return dbs[highest_version]

    return None


def filter_db_names(paths: List[str]) -> List[str]:
    """Returns a filtered list of `paths`, where every name matches our format.

    Args:
        paths: A list of file names.
    """
    return [
        db_path
        for db_path in paths
        if VERSION_RE.match(os.path.basename(db_path))
    ]
