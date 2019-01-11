import random
import time
from datetime import datetime
from pathlib import Path

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SQLiteStorage
from raiden.tests.utils import factories
from raiden.transfer.state_change import ActionInitChain
from raiden.utils.upgrades import UpgradeManager


def setup_storage(db_path):
    storage = SQLiteStorage(str(db_path), JSONSerializer())
    time.sleep(1)
    storage.write_state_change(
        ActionInitChain(
            pseudo_random_generator=random.Random(),
            block_number=1,
            our_address=factories.make_address(),
            chain_id=1,
        ),
        datetime.utcnow().isoformat(timespec='milliseconds'),
    )
    return storage


def test_upgrade_v16_to_v17(tmp_path):
    db_path = tmp_path / Path('test.db')
    storage = setup_storage(db_path)
    manager = UpgradeManager(
        db_filename=str(db_path),
        current_version=16,
        new_version=17,
    )
    manager.run()

    snapshot = storage.get_latest_state_snapshot()
    assert snapshot is not None
