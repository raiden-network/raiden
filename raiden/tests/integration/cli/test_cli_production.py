import pexpect
import pytest
from eth_utils import to_checksum_address

from raiden.constants import Environment
from raiden.settings import RED_EYES_CONTRACT_VERSION
from raiden.tests.integration.cli.util import (
    expect_cli_normal_startup,
    expect_cli_successful_connected,
    expect_cli_until_acknowledgment,
)

EXPECTED_DEFAULT_ENVIRONMENT_VALUE = Environment.PRODUCTION.value

pytestmark = pytest.mark.parametrize(
    'cli_tests_contracts_version',
    [RED_EYES_CONTRACT_VERSION],
    scope='module',
)


@pytest.mark.timeout(65)
def test_cli_full_init(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        # expect the default mode
        expect_cli_normal_startup(child, EXPECTED_DEFAULT_ENVIRONMENT_VALUE)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{'keystore_path': '.'}])
def test_cli_wrong_keystore_path(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        expect_cli_until_acknowledgment(child)
        child.expect('No Ethereum accounts found in the provided keystore directory')
    except pexpect.TIMEOUT as e:
        print('PEXPECT timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('removed_args', [['password_file']])
def test_cli_missing_password_file_enter_password(raiden_testchain, cli_args, raiden_spawner):
    print(cli_args)
    child = raiden_spawner(cli_args)
    try:
        expect_cli_until_acknowledgment(child)
        child.expect('Enter the password to unlock')
        with open(raiden_testchain['password_file'], 'r') as password_file:
            password = password_file.readline()
            child.sendline(password)
        expect_cli_successful_connected(child, EXPECTED_DEFAULT_ENVIRONMENT_VALUE)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(65)
@pytest.mark.parametrize('removed_args', [['data_dir']])
def test_cli_missing_data_dir(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        expect_cli_normal_startup(child, EXPECTED_DEFAULT_ENVIRONMENT_VALUE)
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{'eth_rpc_endpoint': 'http://8.8.8.8:2020'}])
def test_cli_wrong_rpc_endpoint(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        expect_cli_until_acknowledgment(child)
        child.expect(".*Could not contact the Ethereum node through JSON-RPC.")
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{'network_id': '42'}])
def test_cli_wrong_network_id_try_kovan(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        expect_cli_until_acknowledgment(child)
        child.expect(
            ".*The chosen ethereum network 'kovan' differs from the ethereum "
            "client 'smoketest'",
        )
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()


@pytest.mark.timeout(35)
@pytest.mark.parametrize('changed_args', [{
    'tokennetwork_registry_contract_address': to_checksum_address(
        '0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359',
    ),
}])
def test_cli_registry_address_without_deployed_contract(cli_args, raiden_spawner):
    child = raiden_spawner(cli_args)
    try:
        expect_cli_until_acknowledgment(child)
        child.expect('.*contract does not contain code')
    except pexpect.TIMEOUT as e:
        print('Timed out at', e)
    finally:
        child.close()
