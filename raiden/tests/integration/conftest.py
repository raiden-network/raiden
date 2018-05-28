# -*- coding: utf-8 -*-
from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.matrix import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403


def pytest_addoption(parser):
    parser.addoption(
        '--local-matrix',
        action='store',
        dest='local_matrix',
        default=None,
        help=(
            'Path to script/command that starts a local matrix server. If given, '
            'the integration tests will run using matrix instead of udp.'
        )
    )

    parser.addoption(
        '--matrix-host',
        action='store',
        dest='matrix_host',
        default='localhost',
        help="Host name of local matrix server if used, default: 'localhost'"
    )

    parser.addoption(
        '--matrix-port',
        action='store',
        dest='matrix_port',
        default=8008,
        help='Port of local matrix server if used, default: 8008'
    )


def pytest_generate_tests(metafunc):
    local_matrix = metafunc.config.getoption('local_matrix')

    if local_matrix is not None and 'local_matrix' in metafunc.fixturenames:

        metafunc.parametrize('local_matrix', (local_matrix,))
        metafunc.parametrize('use_matrix', (True,))
        metafunc.parametrize('use_local_matrix_server', (True,))

        metafunc.parametrize('matrix_host', (metafunc.config.getoption('matrix_host'),))
        metafunc.parametrize('matrix_port', (metafunc.config.getoption('matrix_port'),))
