import pexpect
import pytest

from raiden.constants import Environment
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION
from raiden.tests.integration.cli.util import expect_cli_normal_startup

pytestmark = pytest.mark.parametrize(
    'cli_tests_contracts_version',
    [DEVELOPMENT_CONTRACT_VERSION],
    scope='module',
)


@pytest.mark.timeout(65)
@pytest.mark.parametrize('changed_args', [{
    'environment_type': Environment.DEVELOPMENT.value,
}])
def test_cli_change_environment_type(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        # expect the provided mode
        expect_cli_normal_startup(child, Environment.DEVELOPMENT.value)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()
