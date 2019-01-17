from raiden.tests.integration.fixtures.blockchain import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.raiden_network import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.smartcontracts import *  # noqa: F401,F403
from raiden.tests.integration.fixtures.transport import *  # noqa: F401,F403
from raiden_libs.test.fixtures.web3 import patch_genesis_gas_limit  # noqa: F401, F403


def pytest_generate_tests(metafunc):
    if 'transport' in metafunc.fixturenames:
        transport = metafunc.config.getoption('transport')
        transport_and_privacy = list()

        # ob-review
        # skipping tests depending on fixtures is a novel use for me
        # not sure what to think here - is this speeding up tests considerably?
        # Otherwise I would tend to that in the test to be skipped directly if runtime
        # information is needed and otherwise as a marker
        # avoid collecting test if 'skip_if_not_*'
        if transport in ('udp', 'all') and 'skip_if_not_matrix' not in metafunc.fixturenames:
            transport_and_privacy.append(('udp', None))

        if transport in ('matrix', 'all') and 'skip_if_not_udp' not in metafunc.fixturenames:
            if 'public_and_private_rooms' in metafunc.fixturenames:
                transport_and_privacy.extend([('matrix', False), ('matrix', True)])
            else:
                transport_and_privacy.append(('matrix', False))

        metafunc.parametrize('transport,private_rooms', transport_and_privacy)
