# -*- coding: utf-8 -*-
from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403

import pytest

from pathlib import Path

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

        if transport in ('matrix', 'all') and 'skip_if_not_udp' not in metafunc.fixturenames:
            command = metafunc.config.getoption('local_matrix')
            if command is None:
                project_root = Path(__file__).absolute().parents[3]
                command = project_root.joinpath('.synapse', 'run.sh').as_posix()
            transport_config.append(
                TransportConfig(
                    protocol=TransportProtocol.MATRIX,
                    parameters=MatrixTransportConfig(
                        command=command,
                        host=metafunc.config.getoption('matrix_host'),
                        port=metafunc.config.getoption('matrix_port')
                    )
                )
            )

        metafunc.parametrize('transport_config', transport_config)

        if not transport_config:
            pytest.skip(f"Test does not apply to transport setting '{transport}'")
