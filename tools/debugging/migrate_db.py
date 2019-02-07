"""

"""
import click
import gevent
import structlog

from raiden.storage import serialize, sqlite
from raiden.utils.upgrades import UpgradeManager

log = structlog.get_logger(__name__)

database_path = ""


def upgrade_db(current_version: int, new_version: int):
    log.debug(f'Upgrading database from v{current_version} to v{new_version}')
    # Prevent unique constraint error in DB when recording raiden "runs"
    gevent.sleep(1)
    manager = UpgradeManager(
        db_filename=database_path,
        current_version=current_version,
        new_version=new_version,
    )
    try:
        manager.run()
    except Exception as e:
        manager.restore_backup()
        log.error(f'Failed to upgrade database: {str(e)}')


def migrate_db(storage):
    storage.register_upgrade_callback(upgrade_db)
    storage.maybe_upgrade()


@click.command(help=__doc__)
@click.argument(
    'db-file',
    type=click.Path(exists=True),
)
def main(db_file):
    global database_path
    database_path = db_file
    migrate_db(
        storage=sqlite.SerializedSQLiteStorage(db_file, serialize.JSONSerializer()),
    )


if __name__ == "__main__":
    main()
