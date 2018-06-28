from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403

import pytest

from raiden.tests.integration.fixtures.transport import (
    MatrixTransportConfig,
    TransportConfig,
    TransportProtocol,
)
from raiden.tests.utils.patch_connection_pool import patch_http_connection_pool


def pytest_generate_tests(metafunc):

    if 'transport_config' in metafunc.fixturenames:
        transport = metafunc.config.getoption('transport')
        transport_config = list()

        if transport in ('udp', 'all'):
            transport_config.append(
                TransportConfig(protocol=TransportProtocol.UDP, parameters=None),
            )

        if transport in ('matrix', 'all') and 'skip_if_not_udp' not in metafunc.fixturenames:
            command = metafunc.config.getoption('local_matrix')
            transport_config.append(
                TransportConfig(
                    protocol=TransportProtocol.MATRIX,
                    parameters=MatrixTransportConfig(
                        command=command,
                        server=metafunc.config.getoption('matrix_server'),
                    ),
                ),
            )

        metafunc.parametrize('transport_config', transport_config)

        if not transport_config:
            pytest.skip(f"Test does not apply to transport setting '{transport}'")


# since we are running everything in a single thread, patch urrlib to allow more connections
patch_http_connection_pool(maxsize=256)
