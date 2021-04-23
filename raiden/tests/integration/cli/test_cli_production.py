import pytest
from eth_utils import to_canonical_address

from raiden.constants import Environment
from raiden.settings import RAIDEN_CONTRACT_VERSION
from raiden.tests.integration.cli.util import (
    expect_cli_normal_startup,
    expect_cli_successful_connected,
    expect_cli_until_acknowledgment,
)
from raiden.utils.formatting import to_checksum_address

EXPECTED_DEFAULT_ENVIRONMENT = Environment.PRODUCTION

pytestmark = [
    pytest.mark.parametrize(
        "cli_tests_contracts_version", [RAIDEN_CONTRACT_VERSION], scope="module"
    ),
    pytest.mark.parametrize("environment_type", [EXPECTED_DEFAULT_ENVIRONMENT], scope="module"),
]


def test_cli_full_init(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    # expect the default mode
    expect_cli_normal_startup(child, EXPECTED_DEFAULT_ENVIRONMENT.value)


@pytest.mark.parametrize("changed_args", [{"keystore_path": "."}])
def test_cli_wrong_keystore_path(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_until_acknowledgment(child)
    child.expect("No Ethereum accounts found in the provided keystore directory")


@pytest.mark.parametrize("removed_args", [["password_file"]])
def test_cli_missing_password_file_enter_password(raiden_testchain, cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)

    expect_cli_until_acknowledgment(child)
    child.expect("Enter the password to unlock")
    with open(raiden_testchain["password_file"], "r") as password_file:
        password = password_file.readline()
        child.sendline(password)
    expect_cli_successful_connected(child, EXPECTED_DEFAULT_ENVIRONMENT.value)


@pytest.mark.parametrize("removed_args", [["data_dir"]])
def test_cli_missing_data_dir(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_normal_startup(child, EXPECTED_DEFAULT_ENVIRONMENT.value)


@pytest.mark.parametrize("changed_args", [{"eth_rpc_endpoint": "http://8.8.8.8:2020"}])
def test_cli_wrong_rpc_endpoint(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)

    expect_cli_until_acknowledgment(child)
    child.expect(".*Communicating with an external service failed.")


@pytest.mark.parametrize("changed_args", [{"chain_id": "42"}])
def test_cli_wrong_chain_id_try_kovan(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    expect_cli_until_acknowledgment(child)
    child.expect("The configured network.*differs from the Ethereum client's network")


@pytest.mark.parametrize(
    "changed_args",
    [
        {
            "user_deposit_contract_address": to_checksum_address(
                to_canonical_address("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359")
            )
        }
    ],
)
def test_cli_registry_address_without_deployed_contract(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)

    expect_cli_until_acknowledgment(child)
    child.expect(".* does not contain code")
