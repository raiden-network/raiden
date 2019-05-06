import os
import os.path

from raiden.constants import RAIDEN_DB_VERSION


def database_from_privatekey(base_dir, app_number):
    """ Format a database path based on the private key and app number. """
    dbpath = os.path.join(base_dir, f"app{app_number}", f"v{RAIDEN_DB_VERSION}_log.db")
    os.makedirs(os.path.dirname(dbpath))

    return dbpath
