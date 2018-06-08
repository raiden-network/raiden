# -*- coding: utf-8 -*-
from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403


from raiden.tests.integration.fixtures.transport import (
    MatrixTransportConfig,
    TransportConfig,
    TransportProtocol
)


def pytest_generate_tests(metafunc):

    if 'transport_config' in metafunc.fixturenames:
        transport = metafunc.config.getoption('transport')
        transport_config = list()

        if transport in ('udp', 'all'):
            transport_config.append(
                TransportConfig(protocol=TransportProtocol.UDP, parameters=None)
            )

        if transport in ('matrix', 'all'):
            transport_config.append(
                TransportConfig(
                    protocol=TransportProtocol.MATRIX,
                    parameters=MatrixTransportConfig(
                        command=metafunc.config.getoption('local_matrix'),
                        host=metafunc.config.getoption('matrix_host'),
                        port=metafunc.config.getoption('matrix_port')
                    )
                )
            )

        metafunc.parametrize('transport_config', transport_config)
