import os


def get_artifacts_storage(default):
    return os.environ.get("RAIDEN_TESTS_ETH_LOGSDIR", default)
