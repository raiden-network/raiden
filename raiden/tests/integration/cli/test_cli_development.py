import pytest

from raiden.constants import Environment
from raiden.settings import DEVELOPMENT_CONTRACT_VERSION
from raiden.tests.integration.cli.util import (
    expect_cli_normal_startup,
    expect_cli_successful_connected,
    expect_cli_until_account_selection,
)

pytestmark = [
    pytest.mark.parametrize(
        "cli_tests_contracts_version", [DEVELOPMENT_CONTRACT_VERSION], scope="module"
    ),
    pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT.value], scope="module"),
]


@pytest.mark.timeout(45)
def test_cli_full_init_dev(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_normal_startup(child, Environment.DEVELOPMENT.value)


@pytest.mark.timeout(45)
@pytest.mark.parametrize("removed_args", [["address"]])
def test_cli_manual_account_selection(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_until_account_selection(child)
    expect_cli_successful_connected(child, Environment.DEVELOPMENT.value)
