from raiden.storage.versions import older_db_file


def test_older_db_file():
    assert older_db_file(['v10_log.db', 'v9_log.db']) == 'v10_log.db'
    assert older_db_file(['v9_log.db', 'v10_log.db']) == 'v10_log.db'
    assert older_db_file(['v1_log.db', 'v9_log.db']) == 'v9_log.db'
    assert older_db_file(['v9_log.db', 'v1_log.db']) == 'v9_log.db'

    assert older_db_file([]) is None
    assert older_db_file(['a']) is None
    assert older_db_file(['.db']) is None
    assert older_db_file(['v9.db']) is None
    assert older_db_file(['9_log.db']) is None
    assert older_db_file(['va9_log.db']) is None
    assert older_db_file(['v9a_log.db']) is None
