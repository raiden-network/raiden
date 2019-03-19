import os.path
import re

from raiden.utils.typing import Optional

VERSION_RE = re.compile(r'^v(\d+)_log[.]db$')


def older_db_file(paths) -> Optional[str]:
    """Returns the path with matches our database naming convention and has the
    highest version number or None.
    """
    dbs = {}
    for db_path in paths:
        # Ignore files that don't match our naming format
        matches = VERSION_RE.search(os.path.basename(db_path))
        if not matches:
            continue

        try:
            version = int(matches.group(1))
        except ValueError:
            continue

        dbs[version] = db_path

    if dbs:
        highest_version = sorted(dbs)[-1]
        return dbs[highest_version]

    return None
