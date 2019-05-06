import pytest

from raiden.storage.versions import filter_db_names, latest_db_file


def test_latest_db_file():
    assert latest_db_file(["v10_log.db", "v9_log.db"]) == "v10_log.db"
    assert latest_db_file(["v9_log.db", "v10_log.db"]) == "v10_log.db"
    assert latest_db_file(["v1_log.db", "v9_log.db"]) == "v9_log.db"
    assert latest_db_file(["v9_log.db", "v1_log.db"]) == "v9_log.db"
    assert latest_db_file([]) is None

    values = ["a", ".db", "v9.db", "9_log.db", "va9_log.db", "v9a_log.db"]
    for invalid_value in values:
        with pytest.raises(AssertionError):
            latest_db_file([invalid_value])


def test_filter_db_names():
    assert filter_db_names(["v10_log.db", "v9_log.db"]) == ["v10_log.db", "v9_log.db"]
    assert filter_db_names(["v9_log.db", "v10_log.db"]) == ["v9_log.db", "v10_log.db"]
    assert filter_db_names(["v1_log.db", "v9_log.db"]) == ["v1_log.db", "v9_log.db"]
    assert filter_db_names(["v9_log.db", "v1_log.db"]) == ["v9_log.db", "v1_log.db"]

    values = [[], ["a"], [".db"], ["v9.db"], ["9_log.db"], ["va9_log.db"], ["v9a_log.db"]]
    for invalid_value in values:
        assert filter_db_names(invalid_value) == []
