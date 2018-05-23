import pytest

from mirakuru import TCPExecutor


@pytest.fixture
def use_local_matrix_server():
    """
    If True, try to test with a real client and start a fresh local
    matrix server for each test. This should be used for integration
    tests only.
    If False, use the mock matrix client.
    """
    return False


# the empty fixtures are overwritten in integration/conftest.py
@pytest.fixture
def local_matrix():
    return None


@pytest.fixture
def matrix_host():
    return None


@pytest.fixture
def matrix_port():
    return None


@pytest.fixture
def local_matrix_server(
        use_matrix,
        use_local_matrix_server,
        local_matrix,
        matrix_host,
        matrix_port
):

    if not (use_matrix and use_local_matrix_server):
        yield None
        return

    assert local_matrix is not None, \
        "No command to start the local matrix server given. (--local-matrix option)"

    server = TCPExecutor(
        local_matrix,
        host=matrix_host,
        port=matrix_port,
        timeout=120,
        sleep=0.1,
        shell=True
    )

    server.start()
    yield 'http://{}:{}'.format(matrix_host, matrix_port)
    server.stop()
