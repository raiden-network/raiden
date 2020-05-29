import pytest

from raiden.constants import Environment
from raiden.settings import RAIDEN_CONTRACT_VERSION
from raiden.tests.integration.cli.util import (
    expect_cli_normal_startup,
    expect_cli_successful_connected,
    expect_cli_until_account_selection,
)

pytestmark = [
    pytest.mark.parametrize(
        "cli_tests_contracts_version", [RAIDEN_CONTRACT_VERSION], scope="module"
    ),
    pytest.mark.parametrize("environment_type", [Environment.DEVELOPMENT], scope="module"),
    # This is a bit awkward, the default `chain_id` for the `raiden_testchain` and
    # `local_matrix_servers` fixtures don't align. Therefore we force it to "smoketest" here.
    pytest.mark.parametrize("chain_id", ["smoketest"]),
]


def test_cli_full_init_dev(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_normal_startup(child, Environment.DEVELOPMENT.value)


@pytest.mark.parametrize("removed_args", [["address"]])
def test_cli_manual_account_selection(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_until_account_selection(child)
    expect_cli_successful_connected(child, Environment.DEVELOPMENT.value)
