import random
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.state_change import ActionInitChain
from raiden.utils.upgrades import UpgradeManager


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path), JSONSerializer())

    chain_state_data = Path(__file__).parent / 'data/v16_chainstate.json'
    chain_state = chain_state_data.read_text()

    storage.write_state_change(
        ActionInitChain(
            pseudo_random_generator=random.Random(),
            block_number=1,
            our_address=factories.make_address(),
            chain_id=1,
        ),
        datetime.utcnow().isoformat(timespec='milliseconds'),
    )

    cursor = storage.conn.cursor()
    cursor.execute(
        """
        INSERT INTO state_snapshot(identifier, statechange_id, data)
        VALUES(1, 1, ?)
        """, (chain_state,),
    )
    storage.conn.commit()
    return storage


def test_upgrade_v16_to_v17(tmp_path):
    db_path = tmp_path / Path('test.db')

    old_db_filename = tmp_path / Path('v16_log.db')
    with patch('raiden.utils.upgrades.older_db_file') as older_db_file:
        older_db_file.return_value = str(old_db_filename)
        storage = setup_storage(str(old_db_filename))
        with patch('raiden.storage.sqlite.RAIDEN_DB_VERSION', new=16):
            storage.update_version()

    manager = UpgradeManager(db_filename=str(db_path))
    manager.run()

    storage = SQLiteStorage(str(db_path), JSONSerializer())
    snapshot = storage.get_latest_state_snapshot()
    assert snapshot is not None
