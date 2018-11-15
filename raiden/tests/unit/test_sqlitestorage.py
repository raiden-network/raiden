from datetime import datetime, timedelta
from unittest.mock import patch

from raiden.storage.sqlite import SQLiteStorage


def test_log_raiden_run():
    with patch('raiden.storage.sqlite.get_system_spec') as get_speck_mock:
        get_speck_mock.return_value = dict(raiden='1.2.3')
        store = SQLiteStorage(':memory:', None)
    cursor = store.conn.cursor()
    cursor.execute('SELECT started_at, raiden_version FROM runs')
    run = cursor.fetchone()
    now = datetime.utcnow()
    assert now - timedelta(seconds=2) <= run[0] <= now, f'{run[0]} not right before {now}'
    assert run[1] == '1.2.3'
